### Usage:


1. Require the package
```
const Furs = require('furs-invoices');
```

2. Initialize the library
```
const furs = Furs({
  env: 'production',
  certPath: 'path/to/your/certificate',
  certPass: 'certificate-password',
  taxID: 'your tax ID',
  premiseID: 'your furs registered business premise ID',
  deviceID: 'your furs registered electronic device ID',
  taxRate: 22.00
});
```

3. Generate an invoice and obtain EOR, ZOI and QR
```
const invoice = {
  id: 1,
  amount: 5,
  date: moment()
}
const invoiceData = await furs.registerInvoice(invoice.id, invoice.amount, invoice.date);
```

Original author:
Boštjan Pišler @ [Studio 404](http://studio404.net)
