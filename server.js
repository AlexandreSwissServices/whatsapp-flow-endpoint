const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

function verifyFacebookSignature(req, res, next) {
  const signature = req.headers['x-hub-signature-256'];
  if (!signature) return res.status(400).send('Signature manquante.');

  const elements = signature.split('=');
  const signatureHash = elements[1];

  const expectedHash = crypto
    .createHmac('sha256', process.env.APP_SECRET)
    .update(req.rawBody)
    .digest('hex');

  if (signatureHash !== expectedHash) return res.status(403).send('Signature invalide.');

  next();
}

app.post('/webhook', verifyFacebookSignature, (req, res) => {
  console.log('Webhook reçu et vérifié :', req.body);
  res.sendStatus(200);
});

app.listen(port, () => {
  console.log(`Serveur démarré sur le port ${port}`);
});
