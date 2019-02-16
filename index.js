// http://www.datoteke.fu.gov.si/dpr/files/TehnicnaDokumentacijaVer1.6.pdf
const fs = require('fs');
const request = require('request-promise-native');
const path = require('path');
const uuidv4 = require('uuid').v4;
const validate = require('jsonschema').validate;
const jsonwebtoken = require('jsonwebtoken');
const moment = require('moment');
const md5 = require('md5');
const forge = require('node-forge');
const hexToDecimal = require('biguint-format');
const jsrsasign = require('jsrsasign');

const CERTS = {
  production: {
    tlsPubKey: './certs/production/blagajne.fu.gov.si.cer',
    signPubKey: './certs/production/DavPotRac.pem',
    authority: './certs/production/sigov-ca2.xcert.crt',
    root: './certs/production/si-trust-root.crt'
  },
  test: {
    tlsPubKey: './certs/test/test-tls.cer',
    signPubKey: './certs/test/test-sign.pem',
    authority: './certs/test/sitest-ca.cer',
    root: './certs/test/TaxCATest.cer'
  }
}

const Furs = ({ env, certPath, certPass, taxID, premiseID, deviceID, taxRate }) => {

  const url = env === 'production' ? 'https://blagajne.fu.gov.si:9003/v1/cash_registers' : 'https://blagajne-test.fu.gov.si:9002/v1/cash_registers';
  const dtf = 'Y-MM-DD[T]HH:mm:ss[Z]';

  // not needed for now
  const tlsCertFile = path.resolve(__dirname, env === 'production' ? CERTS.production.tlsPubKey : CERTS.test.tlsPubKey);
  const myCertFile = certPath;
  const passphrase = certPass;
  const fursCertPemFile = path.resolve(__dirname, env === 'production' ? CERTS.production.signPubKey : CERTS.test.signPubKey);
  const rootCert = path.resolve(__dirname, env === 'production' ? CERTS.production.root : CERTS.test.root);
  const authorityCert = path.resolve(__dirname, env === 'production' ? CERTS.production.authority : CERTS.test.authority);

  const requestOptions = {
    requestCert: true,
    ca: [
      fs.readFileSync(authorityCert),
      fs.readFileSync(rootCert)
    ],
    checkServerIdentity: function (host, cert) {
      return undefined; // instead of rejectUnauthorized
    },
    pfx: fs.readFileSync(myCertFile),
    passphrase,
    headers: {
      'content-type': 'application/json; UTF-8',
    },
    json: true
  }

  const TaxNumber = taxID;
  const BusinessPremiseID = premiseID;
  const ElectronicDeviceID = deviceID;
  const TaxRate = taxRate

  // Parse pem and data from p12
  let key;
  const p12Der = forge.util.decode64(fs.readFileSync(myCertFile).toString('base64'));
  const p12Asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, passphrase);
  const bags = p12.getBags({bagType: forge.pki.oids.certBag});
  const cert = bags[forge.pki.oids.certBag][0];

  // Serial number
  let serial = hexToDecimal(cert['cert']['serialNumber'], 'dec');

  // Header issuer and subject
  const certCNs = {
    'issuer_name': cert['cert']['issuer'],
    'subject_name': cert['cert']['subject'],
  }

  const pkcs12Asn1 = forge.asn1.fromDer(p12Der);
  const pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, false, passphrase);
  let map = {};

  for (let sci = 0; sci < pkcs12.safeContents.length; ++sci) {
    let safeContents = pkcs12.safeContents[sci];

    for (let sbi = 0; sbi < safeContents.safeBags.length; ++sbi) {
      let safeBag = safeContents.safeBags[sbi];
      let localKeyId = null;

      if (safeBag.attributes.localKeyId) {
        localKeyId = forge.util.bytesToHex(safeBag.attributes.localKeyId[0]);

        if (!(localKeyId in map)) {
          map[localKeyId] = {
            privateKey: null,
            certChain: [],
          };
        }
      } else {
        continue;
      }

      if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
        map[localKeyId].privateKey = safeBag.key;
      } else if (safeBag.type === forge.pki.oids.certBag) {
        map[localKeyId].certChain.push(safeBag.cert);
      }
    }
  }

  for (let localKeyId in map) {
    let entry = map[localKeyId];

    if (entry.privateKey) {
      let privateKeyP12Pem = forge.pki.privateKeyToPem(entry.privateKey);
      key = privateKeyP12Pem;
    }
  }

  let header = {
    alg: 'RS256',
    subject_name: '',
    issuer_name: '',
    serial,
  }

  const cnTypes = ['subject_name', 'issuer_name'];

  cnTypes.forEach(t => {
    for (let i = 0; i < certCNs[t].attributes.length; i++) {
      let attributes = certCNs[t].attributes[i];

      let tName = 'name';
      if ('shortName' in attributes) tName = 'shortName';

      header[t] = header[t] + ',' + attributes[tName] + '=' + attributes['value'];
    }

    header[t] = header[t].substring(1);
  });

  //invoice
  return {
    testConnection: async () => {
      const body = {
        EchoRequest: 'furs'
      };
      const response = await request.post(url + '/echo', {
        body,
        ...requestOptions
      });
      
      return response.EchoRequest === body.EchoRequest;
    },

    registerInvoice: async (InvoiceAmount, InvoiceNumber, InvoiceDate) => {
      InvoiceAmount = parseFloat(InvoiceAmount)
      InvoiceNumber = String(InvoiceNumber)

      const IssueDateTime = moment(InvoiceDate);
      
      // Generate ZOI value
      let ZOI = '' + TaxNumber + IssueDateTime.format('DD.MM.Y HH:mm:ss') + InvoiceNumber + BusinessPremiseID + ElectronicDeviceID + InvoiceAmount;
      
      let sig = new jsrsasign.KJUR.crypto.Signature({alg: 'SHA256withRSA'});
      sig.init(key);
      sig.updateString(ZOI);
      
      ZOI = md5(sig.sign());
      
      // Invoice data
      const invoice = {
      InvoiceRequest: {
        Header: {
          MessageID: uuidv4(),
          DateTime: moment().format(dtf),
        },
        Invoice: {
          TaxNumber,
          IssueDateTime: moment(IssueDateTime).format(dtf),
          NumberingStructure: 'B',
          InvoiceIdentifier: {
            BusinessPremiseID,
            ElectronicDeviceID,
            InvoiceNumber
          },
          InvoiceAmount,
          PaymentAmount: InvoiceAmount,
          TaxesPerSeller: [{
            VAT: [{
              TaxRate,
              TaxableAmount: Math.ceil(InvoiceAmount / (1 + TaxRate/100) * 100) / 100,
              TaxAmount: (InvoiceAmount * 100 - Math.ceil(InvoiceAmount / (1 + TaxRate/100) * 100)) / 100
            }]
          }],
          ProtectedID: ZOI,
        }
      }
      }

      // Generate QR code value
      let QR = hexToDecimal(ZOI, 'dec');
      while (QR.length < 39) QR = '0' + QR;

      QR = QR + moment(IssueDateTime, 'DD.MM.Y HH:mm:ss').format('YYMMDDHHmmss');

      QR += TaxNumber;

      let controlNum = 0;
      for (let i = 0; i < QR.length; i++) controlNum += parseInt(QR[i]);
      controlNum %= 10;
      QR += controlNum;

      let payload;
      payload = invoice;


      // Validate payload
      let schema = path.resolve(__dirname, 'FiscalVerificationSchema.json');
      schema = JSON.parse(fs.readFileSync(schema));
      const validation = validate(payload, schema);

      if (!!validation.errors && validation.errors.length) {
        console.log(validation.errors)
        throw new Error('FURS payload validation failed');
      }

      // Generate JWT
      let token = jsonwebtoken.sign(payload, key, {header, algorithm: 'RS256', noTimestamp: true});

      let body = {
        token
      };
      
      const responseTokenized = await request.post(url + '/invoices', {
        body,
        ...requestOptions
      })

      const response = jsonwebtoken.verify(responseTokenized.token, fs.readFileSync(fursCertPemFile), {algorithms: ['RS256']});
      const EOR = response.InvoiceResponse.UniqueInvoiceID
      
      if(EOR === undefined) {
        console.error('FURS ERROR', response);
        throw new Error('Unable to register invoice with FURS.');
      }

      return { ZOI, EOR, QR }
    }
  }
}

module.exports = Furs

