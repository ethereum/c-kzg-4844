import kzg from './kzg';

describe('C-KZG', () => {
  describe('Trusted setup', () => {
    it('can both load and free', () => {
      const kzgSettingsHandle = kzg.loadTrustedSetup(
        '../../src/trusted_setup.txt',
      );
      kzg.freeTrustedSetup(kzgSettingsHandle);
      expect(kzgSettingsHandle).toBeDefined();
    });
  });
});
