const $ = (id) => document.getElementById(id);

$('new').addEventListener('click', async () => {
  const m = await window.cryptec.generateMnemonic(128);
  $('mn').innerText = m;
});

$('addr').addEventListener('click', () => {
  const mn = $('mn').innerText;
  if (!mn) return alert('generate or enter mnemonic first');
  const a = window.cryptec.firstReceiveAddress(mn);
  $('addrbox').innerText = a;
});

$('psbt').addEventListener('click', async () => {
  const mn = $('mn').innerText;
  const to = $('to').value || 'tb1qexampleaddress';
  const sats = parseInt($('sats').value || '1000', 10);
  const psbt = await window.cryptec.createPsbt(mn, to, sats);
  $('out').innerText = psbt;
});
