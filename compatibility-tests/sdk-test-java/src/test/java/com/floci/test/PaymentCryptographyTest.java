package com.floci.test;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.paymentcryptography.PaymentCryptographyClient;
import software.amazon.awssdk.services.paymentcryptography.model.Alias;
import software.amazon.awssdk.services.paymentcryptography.model.As2805KeyVariant;
import software.amazon.awssdk.services.paymentcryptography.model.ExportKeyResponse;
import software.amazon.awssdk.services.paymentcryptography.model.GetParametersForExportResponse;
import software.amazon.awssdk.services.paymentcryptography.model.GetParametersForImportResponse;
import software.amazon.awssdk.services.paymentcryptography.model.ImportKeyResponse;
import software.amazon.awssdk.services.paymentcryptography.model.Key;
import software.amazon.awssdk.services.paymentcryptography.model.KeyAlgorithm;
import software.amazon.awssdk.services.paymentcryptography.model.KeyAttributes;
import software.amazon.awssdk.services.paymentcryptography.model.KeyCheckValueAlgorithm;
import software.amazon.awssdk.services.paymentcryptography.model.KeyClass;
import software.amazon.awssdk.services.paymentcryptography.model.KeyMaterialType;
import software.amazon.awssdk.services.paymentcryptography.model.KeyState;
import software.amazon.awssdk.services.paymentcryptography.model.KeyUsage;
import software.amazon.awssdk.services.paymentcryptography.model.ListKeysResponse;
import software.amazon.awssdk.services.paymentcryptography.model.Tag;
import software.amazon.awssdk.services.paymentcryptography.model.Tr34KeyBlockFormat;
import software.amazon.awssdk.services.paymentcryptography.model.WrappedKeyMaterialFormat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The Payment Cryptography control plane through the AWS SDK.
 *
 * <p>The real service is an awsJson 1.0 service whose operations are targeted by
 * {@code PaymentCryptographyControlPlane.<Operation>}, so a real client is the only way to
 * prove that the wire format, the request shape and the answer shape all agree.
 */
@DisplayName("Payment Cryptography")
class PaymentCryptographyTest {

    private static PaymentCryptographyClient client;
    private static final List<String> keyArns = new ArrayList<>();
    private static final List<String> aliasNames = new ArrayList<>();

    @BeforeAll
    static void setup() {
        client = TestFixtures.paymentCryptographyClient();
    }

    @AfterAll
    static void cleanup() {
        if (client == null) {
            return;
        }
        for (String alias : aliasNames) {
            try {
                client.deleteAlias(a -> a.aliasName(alias));
            } catch (Exception ignored) {
                // The key may already be gone, and real AWS refuses to delete an alias of one.
            }
        }
        for (String arn : keyArns) {
            try {
                client.deleteKey(k -> k.keyIdentifier(arn));
            } catch (Exception ignored) {
                // Real AWS wants a key disabled before it is deleted, and wants it gone by now.
            }
        }
        client.close();
    }

    private static Key createAesKey() {
        return createKey(KeyAlgorithm.AES_256);
    }

    /**
     * A Triple DES key, whose check value is the ANSI X9.24 one.
     *
     * <p>The key is created here because creating it computes that value, and the cipher
     * behind it is the one the native image has to carry.
     */
    private static Key createTdesKey() {
        return createKey(KeyAlgorithm.TDES_2_KEY);
    }

    /** The key a key block is wrapped under. */
    private static Key createWrappingKey() {
        Key key = client.createKey(r -> r
                .keyAttributes(a -> a
                        .keyAlgorithm(KeyAlgorithm.AES_256)
                        .keyClass(KeyClass.SYMMETRIC_KEY)
                        .keyUsage(KeyUsage.TR31_K1_KEY_BLOCK_PROTECTION_KEY)
                        .keyModesOfUse(m -> m.wrap(true).unwrap(true)))
                .exportable(true))
                .key();
        keyArns.add(key.keyArn());
        return key;
    }

    /**
     * The public half of a certificate, held by the service as a key.
     *
     * <p>The certificate is the one the service minted for the occasion, and it stands on
     * its own, so it comes in as the public key of a root certificate.
     */
    private static Key importPublicKey(String certificate) {
        Key key = client.importKey(r -> r
                .keyMaterial(m -> m.rootCertificatePublicKey(b -> b
                        .publicKeyCertificate(certificate)
                        .keyAttributes(a -> a
                                .keyAlgorithm(KeyAlgorithm.RSA_2048)
                                .keyClass(KeyClass.PUBLIC_KEY)
                                .keyUsage(KeyUsage.TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE)
                                .keyModesOfUse(modes -> modes.verify(true))))))
                .key();
        keyArns.add(key.keyArn());
        return key;
    }

    /** A key of the given algorithm, for the data the cipher protects. */
    private static Key createKey(KeyAlgorithm algorithm) {
        Key key = client.createKey(r -> r
                .keyAttributes(a -> a
                        .keyAlgorithm(algorithm)
                        .keyClass(KeyClass.SYMMETRIC_KEY)
                        .keyUsage(KeyUsage.TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY)
                        .keyModesOfUse(m -> m.encrypt(true).decrypt(true)))
                .exportable(true))
                .key();
        keyArns.add(key.keyArn());
        return key;
    }

    /** The key identifier of an ARN: the part after the last slash. */
    private static String keyIdOf(String arn) {
        return arn.substring(arn.lastIndexOf('/') + 1);
    }

    @Test
    void aKeyIsCreatedAndReadBackWithItsModesOfUse() {
        Key created = createAesKey();

        assertThat(created.keyArn()).isNotBlank();
        assertThat(created.keyState()).isEqualTo(KeyState.CREATE_COMPLETE);
        assertThat(created.keyCheckValueAlgorithm()).isEqualTo(KeyCheckValueAlgorithm.CMAC);
        assertThat(created.keyCheckValue()).isNotBlank();
        assertThat(created.enabled()).isTrue();
        assertThat(created.exportable()).isTrue();

        KeyAttributes attributes = created.keyAttributes();
        assertThat(attributes.keyAlgorithm()).isEqualTo(KeyAlgorithm.AES_256);
        assertThat(attributes.keyClass()).isEqualTo(KeyClass.SYMMETRIC_KEY);
        assertThat(attributes.keyUsage()).isEqualTo(KeyUsage.TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY);
        // The modes of use are a nested structure, and the answer must carry the ones asked for.
        assertThat(attributes.keyModesOfUse()).isNotNull();
        assertThat(attributes.keyModesOfUse().encrypt()).isTrue();
        assertThat(attributes.keyModesOfUse().decrypt()).isTrue();

        Key read = client.getKey(k -> k.keyIdentifier(created.keyArn())).key();
        assertThat(read.keyArn()).isEqualTo(created.keyArn());
        assertThat(read.keyAttributes().keyAlgorithm()).isEqualTo(KeyAlgorithm.AES_256);
        assertThat(read.keyAttributes().keyModesOfUse().encrypt()).isTrue();
        assertThat(read.keyAttributes().keyModesOfUse().decrypt()).isTrue();
        assertThat(read.keyCheckValue()).isEqualTo(created.keyCheckValue());
    }

    @Test
    void aTripleDesKeyIsCreatedAndItsCheckValueIsTheX924One() {
        // The check value of a Triple DES key is the ANSI X9.24 one, so it is the leftmost
        // three bytes of encrypting eight zero bytes with the key. The native image has to
        // carry that cipher, so the key is created here and the value is read back.
        Key created = createTdesKey();

        assertThat(created.keyArn()).isNotBlank();
        assertThat(created.keyState()).isEqualTo(KeyState.CREATE_COMPLETE);
        assertThat(created.keyCheckValueAlgorithm()).isEqualTo(KeyCheckValueAlgorithm.ANSI_X9_24);
        assertThat(created.keyCheckValue()).hasSize(6);
        assertThat(created.keyAttributes().keyAlgorithm()).isEqualTo(KeyAlgorithm.TDES_2_KEY);

        Key read = client.getKey(k -> k.keyIdentifier(created.keyArn())).key();
        assertThat(read.keyCheckValue()).isEqualTo(created.keyCheckValue());
        assertThat(read.keyCheckValueAlgorithm()).isEqualTo(KeyCheckValueAlgorithm.ANSI_X9_24);
    }

    @Test
    void theImportAndExportParametersAreServed() {
        GetParametersForImportResponse importParameters = client.getParametersForImport(r -> r
                .keyMaterialType(KeyMaterialType.KEY_CRYPTOGRAM)
                .wrappingKeyAlgorithm(KeyAlgorithm.RSA_2048));

        assertThat(importParameters.importToken()).startsWith("import-token-");
        assertThat(importParameters.wrappingKeyAlgorithm()).isEqualTo(KeyAlgorithm.RSA_2048);
        assertThat(importParameters.wrappingKeyCertificate()).isNotBlank();
        assertThat(importParameters.wrappingKeyCertificateChain()).isNotBlank();
        assertThat(importParameters.parametersValidUntilTimestamp()).isNotNull();

        GetParametersForExportResponse exportParameters = client.getParametersForExport(r -> r
                .keyMaterialType(KeyMaterialType.TR34_KEY_BLOCK)
                .signingKeyAlgorithm(KeyAlgorithm.RSA_2048));

        assertThat(exportParameters.exportToken()).startsWith("export-token-");
        assertThat(exportParameters.signingKeyAlgorithm()).isEqualTo(KeyAlgorithm.RSA_2048);
        assertThat(exportParameters.signingKeyCertificate()).isNotBlank();
        assertThat(exportParameters.signingKeyCertificateChain()).isNotBlank();
        assertThat(exportParameters.parametersValidUntilTimestamp()).isNotNull();
    }

    @Test
    void aKeyLeavesTheServiceAndComesBackThroughTheKeyExchange() {
        Key wrapping = createWrappingKey();
        Key key = createAesKey();

        ExportKeyResponse exported = client.exportKey(r -> r
                .exportKeyIdentifier(key.keyArn())
                .keyMaterial(m -> m.tr31KeyBlock(b -> b.wrappingKeyIdentifier(wrapping.keyArn()))));

        assertThat(exported.wrappedKey().wrappedKeyMaterialFormat())
                .isEqualTo(WrappedKeyMaterialFormat.TR31_KEY_BLOCK);
        assertThat(exported.wrappedKey().wrappingKeyArn()).isEqualTo(wrapping.keyArn());
        assertThat(exported.wrappedKey().keyMaterial()).isNotBlank();
        assertThat(exported.wrappedKey().keyCheckValue()).isNotBlank();

        ImportKeyResponse imported = client.importKey(r -> r
                .keyMaterial(m -> m.tr31KeyBlock(b -> b
                        .wrappingKeyIdentifier(wrapping.keyArn())
                        .wrappedKeyBlock(exported.wrappedKey().keyMaterial()))));

        assertThat(imported.key().keyArn()).isNotBlank();
        assertThat(imported.key().keyAttributes().keyUsage())
                .isEqualTo(KeyUsage.TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY);
    }

    @Test
    void aKeyLeavesTheServiceAndComesBackThroughATr34KeyBlock() {
        // The parameters of the import name the certificate the block is wrapped under, and
        // the parameters of the export name the certificate the block is signed with.
        GetParametersForImportResponse importParameters = client.getParametersForImport(r -> r
                .keyMaterialType(KeyMaterialType.TR34_KEY_BLOCK)
                .wrappingKeyAlgorithm(KeyAlgorithm.RSA_2048));
        GetParametersForExportResponse exportParameters = client.getParametersForExport(r -> r
                .keyMaterialType(KeyMaterialType.TR34_KEY_BLOCK)
                .signingKeyAlgorithm(KeyAlgorithm.RSA_2048));

        // Each certificate is the authority of the party it belongs to.
        Key receiver = importPublicKey(importParameters.wrappingKeyCertificate());
        Key sender = importPublicKey(exportParameters.signingKeyCertificate());

        Key key = createTdesKey();

        ExportKeyResponse exported = client.exportKey(r -> r
                .exportKeyIdentifier(key.keyArn())
                .keyMaterial(m -> m.tr34KeyBlock(b -> b
                        .certificateAuthorityPublicKeyIdentifier(receiver.keyArn())
                        .wrappingKeyCertificate(importParameters.wrappingKeyCertificate())
                        .exportToken(exportParameters.exportToken())
                        .keyBlockFormat(Tr34KeyBlockFormat.X9_TR34_2012)
                        .randomNonce("A1B2C3D4E5F60718"))));

        assertThat(exported.wrappedKey().wrappedKeyMaterialFormat())
                .isEqualTo(WrappedKeyMaterialFormat.TR34_KEY_BLOCK);
        assertThat(exported.wrappedKey().keyMaterial()).isNotBlank();

        ImportKeyResponse imported = client.importKey(r -> r
                .keyMaterial(m -> m.tr34KeyBlock(b -> b
                        .certificateAuthorityPublicKeyIdentifier(sender.keyArn())
                        .signingKeyCertificate(exportParameters.signingKeyCertificate())
                        .importToken(importParameters.importToken())
                        .wrappedKeyBlock(exported.wrappedKey().keyMaterial())
                        .keyBlockFormat(Tr34KeyBlockFormat.X9_TR34_2012)
                        .randomNonce("A1B2C3D4E5F60718"))));

        assertThat(imported.key().keyArn()).isNotBlank();
        assertThat(imported.key().keyAttributes().keyUsage())
                .isEqualTo(KeyUsage.TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY);
    }

    @Test
    void aKeyLeavesTheServiceAndComesBackThroughAnAs2805Cryptogram() {
        Key encryptionKey = client.createKey(r -> r
                .keyAttributes(a -> a
                        .keyAlgorithm(KeyAlgorithm.AES_256)
                        .keyClass(KeyClass.SYMMETRIC_KEY)
                        .keyUsage(KeyUsage.TR31_K0_KEY_ENCRYPTION_KEY)
                        .keyModesOfUse(modes -> modes.wrap(true).unwrap(true)))
                .exportable(true))
                .key();
        keyArns.add(encryptionKey.keyArn());
        Key key = createAesKey();

        ExportKeyResponse exported = client.exportKey(r -> r
                .exportKeyIdentifier(key.keyArn())
                .keyMaterial(m -> m.as2805KeyCryptogram(b -> b
                        .as2805KeyVariant(As2805KeyVariant.PIN_ENCRYPTION_KEY_VARIANT_28)
                        .wrappingKeyIdentifier(encryptionKey.keyArn()))));

        assertThat(exported.wrappedKey().wrappedKeyMaterialFormat())
                .isEqualTo(WrappedKeyMaterialFormat.KEY_CRYPTOGRAM);
        assertThat(exported.wrappedKey().keyMaterial()).isNotBlank();

        ImportKeyResponse imported = client.importKey(r -> r
                .keyMaterial(m -> m.as2805KeyCryptogram(b -> b
                        .as2805KeyVariant(As2805KeyVariant.PIN_ENCRYPTION_KEY_VARIANT_28)
                        .wrappingKeyIdentifier(encryptionKey.keyArn())
                        .wrappedKeyCryptogram(exported.wrappedKey().keyMaterial())
                        .keyAlgorithm(KeyAlgorithm.AES_256)
                        .keyModesOfUse(modes -> modes.encrypt(true).decrypt(true))
                        .exportable(true))));

        assertThat(imported.key().keyArn()).isNotBlank();
        assertThat(imported.key().keyAttributes().keyUsage())
                .isEqualTo(KeyUsage.TR31_P0_PIN_ENCRYPTION_KEY);
    }

    @Test
    void aCryptogramUnderEachSupportedVariantIsServed() {
        // The model names four variants, and the service serves every one of them.
        Key encryptionKey = client.createKey(r -> r
                .keyAttributes(a -> a
                        .keyAlgorithm(KeyAlgorithm.AES_256)
                        .keyClass(KeyClass.SYMMETRIC_KEY)
                        .keyUsage(KeyUsage.TR31_K0_KEY_ENCRYPTION_KEY)
                        .keyModesOfUse(modes -> modes.wrap(true).unwrap(true)))
                .exportable(true))
                .key();
        keyArns.add(encryptionKey.keyArn());
        Key key = createAesKey();

        for (As2805KeyVariant variant : new As2805KeyVariant[] {
                As2805KeyVariant.TERMINAL_MAJOR_KEY_VARIANT_00,
                As2805KeyVariant.DATA_ENCRYPTION_KEY_VARIANT_22,
                As2805KeyVariant.MESSAGE_AUTHENTICATION_KEY_VARIANT_24,
                As2805KeyVariant.PIN_ENCRYPTION_KEY_VARIANT_28}) {
            ExportKeyResponse exported = client.exportKey(r -> r
                    .exportKeyIdentifier(key.keyArn())
                    .keyMaterial(m -> m.as2805KeyCryptogram(b -> b
                            .as2805KeyVariant(variant)
                            .wrappingKeyIdentifier(encryptionKey.keyArn()))));

            assertThat(exported.wrappedKey().wrappedKeyMaterialFormat())
                    .as(variant.toString())
                    .isEqualTo(WrappedKeyMaterialFormat.KEY_CRYPTOGRAM);
            assertThat(exported.wrappedKey().keyMaterial()).isNotBlank();
        }
    }

    @Test
    void aCryptogramUnderAKeyThatIsNotAKeyEncryptionKeyIsRefused() {
        // A key that is neither a key encryption key nor a key block protection key cannot
        // be the one a cryptogram is wrapped under.
        Key dataKey = client.createKey(r -> r
                .keyAttributes(a -> a
                        .keyAlgorithm(KeyAlgorithm.AES_256)
                        .keyClass(KeyClass.SYMMETRIC_KEY)
                        .keyUsage(KeyUsage.TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY)
                        .keyModesOfUse(modes -> modes.encrypt(true).decrypt(true)))
                .exportable(true))
                .key();
        keyArns.add(dataKey.keyArn());
        Key key = createAesKey();

        assertThatThrownBy(() -> client.exportKey(r -> r
                .exportKeyIdentifier(key.keyArn())
                .keyMaterial(m -> m.as2805KeyCryptogram(b -> b
                        .as2805KeyVariant(As2805KeyVariant.PIN_ENCRYPTION_KEY_VARIANT_28)
                        .wrappingKeyIdentifier(dataKey.keyArn())))))
                .isInstanceOf(AwsServiceException.class)
                .hasMessageContaining("key encryption key");
    }

    @Test
    void aKeyIsCreatedDisabledAndWithTags() {
        Key key = client.createKey(r -> r
                .keyAttributes(a -> a
                        .keyAlgorithm(KeyAlgorithm.AES_256)
                        .keyClass(KeyClass.SYMMETRIC_KEY)
                        .keyUsage(KeyUsage.TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY)
                        .keyModesOfUse(m -> m.encrypt(true)))
                .exportable(false)
                .enabled(false)
                .tags(Tag.builder().key("owner").value("team").build()))
                .key();
        keyArns.add(key.keyArn());

        assertThat(key.enabled()).isFalse();
        assertThat(key.exportable()).isFalse();

        Map<String, String> tags = client.listTagsForResource(t -> t.resourceArn(key.keyArn())).tags()
                .stream()
                .collect(Collectors.toMap(Tag::key, Tag::value, (a, b) -> a));
        assertThat(tags).containsEntry("owner", "team");
    }

    @Test
    void theKeysAreListedAPageAtATime() {
        createAesKey();
        createAesKey();

        ListKeysResponse first = client.listKeys(r -> r.maxResults(1));
        assertThat(first.keys()).hasSize(1);
        assertThat(first.nextToken()).isNotNull();

        ListKeysResponse second = client.listKeys(r -> r.maxResults(1).nextToken(first.nextToken()));
        assertThat(second.keys()).hasSize(1);
    }

    @Test
    void theKeysOfTheRegionAreListed() {
        Key key = createAesKey();

        assertThat(client.listKeys(r -> r.maxResults(100)).keys())
                .anySatisfy(listed -> assertThat(listed.keyArn()).isEqualTo(key.keyArn()));
    }

    @Test
    void theAliasOfAKeyIsCreatedAndReadBack() {
        Key key = createAesKey();
        String alias = "alias/compat/" + keyIdOf(key.keyArn());
        aliasNames.add(alias);

        client.createAlias(a -> a.aliasName(alias).keyArn(key.keyArn()));

        Alias read = client.getAlias(a -> a.aliasName(alias)).alias();
        assertThat(read.aliasName()).isEqualTo(alias);
        assertThat(read.keyArn()).isEqualTo(key.keyArn());
        assertThat(client.listAliases(r -> r.maxResults(100)).aliases())
                .anySatisfy(listed -> assertThat(listed.aliasName()).isEqualTo(alias));
    }

    @Test
    void aKeyIsTaggedAndTheTagsAreListed() {
        Key key = createAesKey();

        client.tagResource(t -> t
                .resourceArn(key.keyArn())
                .tags(Tag.builder().key("owner").value("compat").build()));

        Map<String, String> tags = client.listTagsForResource(t -> t.resourceArn(key.keyArn())).tags()
                .stream()
                .collect(Collectors.toMap(Tag::key, Tag::value, (a, b) -> a));
        assertThat(tags).containsEntry("owner", "compat");
    }

    /**
     * A delete answers with the key it deleted, its state DELETE_PENDING and the
     * moment it is deleted, so a caller reads the key and not an empty answer.
     */
    @Test
    void aDeletedKeyIsAnsweredWithTheKey() {
        Key created = createAesKey();

        Key deleted = client.deleteKey(k -> k.keyIdentifier(created.keyArn())).key();

        assertThat(deleted).isNotNull();
        assertThat(deleted.keyArn()).isEqualTo(created.keyArn());
        assertThat(deleted.keyState()).isEqualTo(KeyState.DELETE_PENDING);
        assertThat(deleted.deletePendingTimestamp()).isNotNull();
        assertThat(deleted.enabled()).isFalse();
    }

    /** A listing names the state of the keys it wants, and the service answers with those keys alone. */
    @Test
    void theKeysAreListedByTheirState() {
        Key key = createAesKey();

        assertThat(client.listKeys(r -> r.keyState(KeyState.CREATE_COMPLETE).maxResults(100)).keys())
                .anySatisfy(listed -> assertThat(listed.keyArn()).isEqualTo(key.keyArn()));
        assertThat(client.listKeys(r -> r.keyState(KeyState.DELETE_PENDING).maxResults(100)).keys())
                .noneSatisfy(listed -> assertThat(listed.keyArn()).isEqualTo(key.keyArn()));
    }

    /**
     * The key of an alias is optional, so an update naming no key removes the key
     * the alias names, and the alias stays.
     */
    @Test
    void anAliasIsDetachedFromItsKeyByAnUpdateNamingNoKey() {
        Key key = createAesKey();
        String alias = "alias/compat/detached-" + keyIdOf(key.keyArn());
        aliasNames.add(alias);

        client.createAlias(a -> a.aliasName(alias).keyArn(key.keyArn()));

        Alias detached = client.updateAlias(a -> a.aliasName(alias)).alias();

        assertThat(detached.aliasName()).isEqualTo(alias);
        assertThat(detached.keyArn()).isNull();
        assertThat(client.getAlias(a -> a.aliasName(alias)).alias().aliasName()).isEqualTo(alias);
    }

    /**
     * A region the creating client did not sign for. It has to differ from the
     * region of the suite, or the key would be in that region too and the key
     * would be found.
     */
    private static Region anotherRegion() {
        Region region = TestFixtures.region();
        if (region.id().startsWith("cn-")) {
            return region.id().equals("cn-northwest-1")
                    ? Region.of("cn-north-1") : Region.of("cn-northwest-1");
        }
        return Region.US_WEST_2.equals(region) ? Region.US_EAST_1 : Region.US_WEST_2;
    }

    @Test
    void aKeyOfOneRegionIsNotFoundInAnother() {
        Key key = createAesKey();
        PaymentCryptographyClient elsewhere = TestFixtures.paymentCryptographyClient(anotherRegion());
        try {
            // The key is named by its ARN, as the model takes it: a bare id names no key at all.
            assertThatThrownBy(() -> elsewhere.getKey(k -> k.keyIdentifier(key.keyArn())))
                    .isInstanceOf(AwsServiceException.class)
                    .satisfies(thrown -> assertThat(((AwsServiceException) thrown).awsErrorDetails()
                            .errorCode()).isEqualTo("ResourceNotFoundException"));
        } finally {
            elsewhere.close();
        }
    }
}
