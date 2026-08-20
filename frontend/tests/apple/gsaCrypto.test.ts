import { describe, expect, it } from 'vitest';
import {
  createSrpProof,
  decryptSpd,
  srpPublicKey,
} from '../../src/apple/gsaCrypto';
import { parsePlistLoose } from '../../src/apple/plist';

function hex(value: string): Uint8Array {
  const result = new Uint8Array(value.length / 2);
  for (let i = 0; i < result.length; i++) {
    result[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return result;
}

const privateKey = hex(
  '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
);
const serverPublicKey = hex(
  '0bb3c2b5a44ea51f8b55344dedb23d32025edeb13e6677c27b8ba7244605a1eb' +
    'db5ccbbec83b8baaaf83aa364b15fc2acaf3245dc1640e740466f0bea62200534' +
    'f548d4f3525123e50d86ed02d0daf24c5fa9a91f46b575d343310a5515a0d7aa' +
    'cde1c1fb3b1de876d84756192468b0181d9781b55cad373342af2eb31261406ae' +
    '0cb6fc0d9d1d59784ee9907fdf5d3ea2a411c602c56172aa3bbe8e0b4e6d104' +
    '33e0782809112198b12b51ce55957290cb0c23083fa0b3de1f3d917117b99bef' +
    '578dacc1b246e2e1dd4f116389a297aeda6987824f9f644f3394a6e809acdddc' +
    '583ce1a441c187a40f8a9448197b18b7c01efc11c8d211dc1a77bd53f2a879b',
);

describe('apple/gsaCrypto', () => {
  it('matches the independent pysrp SRP-6a fixture', async () => {
    expect(Buffer.from(srpPublicKey(privateKey)).toString('hex')).toBe(
      '630acdff5d334462d92a29e0b7fa6e20020f3333292f6d3a640f1c7a76ad9d3' +
        '17531c57979952e5736c88db118d060dc0539a812b9b0af3b4002380a9f28ae4' +
        'a7c45a896542de05fbcf76a4e7e0739b9a55d5d6c7aba4f1e1b58729a79bc08' +
        '4d5ff513eaec33ce978f5bad87e579b5a95fc773198e22697b2eadab9eb94f84' +
        'cdcf1fe94ff09f88d4ca46e968bba443ff71167571f19feb052869bd28d7dabf' +
        '963b7fe399a1f70e7e08d00e1a3778ed1dddc3325dd09e05d31e774d1fd295c' +
        '4abfbc613446232004d67cb03d6a034d2ce6ca0a544a0ff5b434b4b4267fa6c' +
        '6d72acbbda2efc1ef1d1fe36d35382b089abe556862aec35b29d3d0cdf359a9c' +
        'fed3',
    );

    const proof = await createSrpProof(
      'test@example.com',
      'correct horse battery staple',
      privateKey,
      {
        salt: new Uint8Array(Array.from({ length: 16 }, (_, i) => i)),
        serverPublicKey,
        iterations: 20_000,
        protocol: 's2k',
      },
    );

    expect(Buffer.from(proof.clientProof).toString('hex')).toBe(
      '8b8b69f8c8ddb7f79886478ba340599da240539b693e6e0fc4eb40aa35659cf6',
    );
    expect(Buffer.from(proof.sessionKey).toString('hex')).toBe(
      'f8359c5fb148c1196d82d36b7e0629a491b58dd241769864774b6c446f9de303',
    );
    expect(Buffer.from(proof.expectedServerProof).toString('hex')).toBe(
      'f2a6578bd80fa569c92aa9edca3fff5e2521d6b2fa90cf32e75d5bf2ad37b4f3',
    );
  });

  it('decrypts an independently generated SPD AES-CBC fixture', async () => {
    const plaintext = await decryptSpd(
      hex('f8359c5fb148c1196d82d36b7e0629a491b58dd241769864774b6c446f9de303'),
      hex(
        '5d78631b1360781d12b9e5bd04b552581e99d61fd94816b474677ac3a4e51fea' +
          'f7502eed37ccc04c239fcc5ff580b6d968ad6ff5e9b31d1f8c659f0b48b894ad' +
          '2cfe13dff3e2fb9092463857548274f6845e68c9b7579056f302df4e476963fa0' +
          'a598e18dbe13b13391ea7114e6e677b002a2955228ef79a65f227933bf9205bd' +
          '6aac0ee40f9b21c104c6d4279b822446bdd7d7043e36390781fd4b4be7d673b7' +
          'fc31ee9f8676776a3685998e5486809873947098988e038fa242daff2239caae4' +
          '3954da322d286d0ee25ae3e1e7db4fab1e73ded656fbce7f9878f143e3d299',
      ),
    );
    const spd = parsePlistLoose(plaintext);

    expect(spd.adsid).toBe('12345');
    expect(spd.GsIdmsToken).toBe('token-value');
    expect(spd.t['com.apple.gs.idms.pet'].token).toBe('pet-value');
  });

  it('matches the independent pysrp s2k_fo fixture', async () => {
    const proof = await createSrpProof(
      'test@example.com',
      'correct horse battery staple',
      privateKey,
      {
        salt: new Uint8Array(Array.from({ length: 16 }, (_, i) => i)),
        serverPublicKey: hex(
          '926cf3fa611712a4eb824d16ec9e127481e7a8941307a73f0c20af1ab611534de' +
            '77898d3237f4d55985f2479971e725a33c8e03e402954c129a1fc4db24ddeb35' +
            '3112f62a39b24f35da84f8afc46d9f610d10574ae44e11ad3cfca7457b6447d' +
            '5d15a38ce38bcba3867c8280c518c8024bfa9f3f3476925c981e7e96c599ffe' +
            '0a8541d2e587ebf5b35dea78b12586fb9299f8ef073a2bf4aa296d1f7ab8bcdc' +
            '500432bc581e7ce917dd800740765577b15897aaeed2ce9a23f6054414e57e539' +
            '1b9a305c4590dd8ad72e3ebe8afb3cecb300bc7de334b34ad282f5f9dddafc97' +
            '78a8cbd1e895bf6ca7dfd92a28ab7f2a8c6843c56a0ddf4079dc216d1b0022ce',
        ),
        iterations: 20_000,
        protocol: 's2k_fo',
      },
    );

    expect(Buffer.from(proof.clientProof).toString('hex')).toBe(
      'bf687984c728b82bd47e389abb49d1c3b82e5295529181cdeeb603ee0c85a3f2',
    );
    expect(Buffer.from(proof.sessionKey).toString('hex')).toBe(
      'a9335986c68d5b04edf6f1fcd40422e76c1347af57d8db9a7fa13dccbfb965e0',
    );
    expect(Buffer.from(proof.expectedServerProof).toString('hex')).toBe(
      'c9206425db3f292a1c6c2ee538d1cdc07bb31935a61e0ee2e609df6473c67c8f',
    );
  });
});
