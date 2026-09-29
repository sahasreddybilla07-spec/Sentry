async function deliver(req) {
  const webhookUrl = req.body.webhookUrl;
  return fetch(webhookUrl);
}

async function profile(req) {
  return db.users.find(req.params.userId);
}
