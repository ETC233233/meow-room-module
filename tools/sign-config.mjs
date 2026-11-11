// 给云下发配置签名（Ed25519）。私钥只从环境变量读，不要写进仓库。
//   node tools/sign-config.mjs keygen                      # 生成一对密钥，打印出来
//   MEOW_SIGN_KEY=<私钥 PKCS8 DER base64> node tools/sign-config.mjs sign <kid> config.json [有效秒数，默认 3600]
// 输出信封 {payload, sig, kid}，由你自己的 CF Worker 作为配置入口返回。
import crypto from 'node:crypto';
import fs from 'node:fs';

const [cmd, ...args] = process.argv.slice(2);
if (cmd === 'keygen') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32); // 32 字节原始公钥
  console.log('公钥（构建时 -p:MeowConfigKeys=<kid>:<这个>）:', raw.toString('base64'));
  console.log('私钥（只放 Worker secret / 环境变量 MEOW_SIGN_KEY）:', privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'));
} else if (cmd === 'sign') {
  const [kid, file, ttl = '3600'] = args;
  const key = crypto.createPrivateKey({ key: Buffer.from(process.env.MEOW_SIGN_KEY || '', 'base64'), format: 'der', type: 'pkcs8' });
  const now = Math.floor(Date.now() / 1000);
  const body = { version: 1, issuedAt: now, expiresAt: now + Number(ttl), ...JSON.parse(fs.readFileSync(file, 'utf8')) };
  const payload = JSON.stringify(body);
  const sig = crypto.sign(null, Buffer.from(payload, 'utf8'), key).toString('base64');
  console.log(JSON.stringify({ payload, sig, kid }));
} else {
  console.error('用法: keygen | sign <kid> <config.json> [ttl秒]');
  process.exit(2);
}
