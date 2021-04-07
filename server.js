const express = require('express');
const bodyParser = require('body-parser');
require('dotenv').config();

const production = require('./startup/prod.js');

const app = express();
app.use(bodyParser.json({ limit: '100mb' }));
app.use(bodyParser.urlencoded({ limit: '100mb', extended: false }));
production(app);
const connectDB = require('./config/db.js');
require('./startup/routes')(app);
app.get('/ping', (req, res) => {
  res.send('pong');
});

const PORT = process.env.PORT || 3000;
connectDB();
app.listen(PORT, () => console.log(`Listening on Port ${PORT}`));
