async function partnerApi() {
  const agent = new https.Agent({ rejectUnauthorized: true });
  return axios.get('https://partner.example/v2', { httpsAgent: agent, timeout: 2500 });
}
