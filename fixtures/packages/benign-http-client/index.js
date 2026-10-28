const https = require('https');

function getWeather(city) {
  const key = process.env.WEATHER_API_KEY;
  return new Promise((resolve, reject) => {
    https.get(`https://api.weather.example.com/v1/now?city=${encodeURIComponent(city)}&key=${key}`, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve(JSON.parse(body)));
    }).on('error', reject);
  });
}

module.exports = { getWeather };
