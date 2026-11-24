async function partnerApi() {
  const agent = new https.Agent({ rejectUnauthorized: false });
  return axios.get('https://partner.example/v2', { httpsAgent: agent });
}
