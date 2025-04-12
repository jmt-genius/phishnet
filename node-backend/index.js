const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Database configuration
const pool = new Pool({
  connectionString: 'postgresql://intervane_owner:npg_m1THX7yDZbLP@ep-floral-pond-a1uscfge-pooler.ap-southeast-1.aws.neon.tech/intervane?sslmode=require'
});

// Test database connection
pool.connect((err, client, release) => {
  if (err) {
    return console.error('Error acquiring client', err.stack);
  }
  console.log('Connected to PostgreSQL database');
  release();
});

// Basic route for testing
app.get('/', (req, res) => {
  res.json({ message: 'PhishNet API is running' });
});

// Check if URL exists
app.get('/api/check-url', async (req, res) => {
  const { url } = req.query;
  
  try {
    const result = await pool.query(
      'SELECT * FROM risk WHERE url = $1',
      [url]
    );
    res.json({ 
      exists: result.rows.length > 0,
      data: result.rows[0] || null
    });
  } catch (error) {
    console.error('Error checking URL:', error);
    res.status(500).json({ success: false, error: 'Failed to check URL' });
  }
});

// Report suspicious URL endpoint
app.post('/api/report', async (req, res) => {
  const { url, ipAddress, cause } = req.body;

  try {
    // Hash the IP address
    const hashedIp = crypto.createHash('sha256').update(ipAddress).digest('hex');

    // First check if URL already exists
    const existingUrl = await pool.query(
      'SELECT * FROM risk WHERE url = $1',
      [url]
    );

    if (existingUrl.rows.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'This URL has already been reported',
        data: existingUrl.rows[0]
      });
    }

    // If URL doesn't exist, insert it
    const result = await pool.query(
      'INSERT INTO risk (url, score, ip_address, cause) VALUES ($1, $2, $3, $4) RETURNING *',
      [url, 0.0, hashedIp, cause] 
    );
    res.json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Error reporting URL:', error);
    res.status(500).json({ success: false, error: 'Failed to report URL' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
