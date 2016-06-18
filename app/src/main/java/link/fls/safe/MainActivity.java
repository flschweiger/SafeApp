/*
 * Copyright (C) 2016 Frederik Schweiger
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package link.fls.safe;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.CardView;
import android.util.Base64;
import android.view.View;
import android.view.animation.OvershootInterpolator;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;

import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.OnClick;

public class MainActivity extends AppCompatActivity
        implements FingerprintDialog.FingerprintDialogCallbacks {

    // This must have 'AndroidKeyStore' as value. Unfortunately there is no predefined constant.
    private static final String ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore";

    // This is the default transformation used throughout this sample project.
    private static final String AES_DEFAULT_TRANSFORMATION =
            KeyProperties.KEY_ALGORITHM_AES + "/" +
                    KeyProperties.BLOCK_MODE_CBC + "/" +
                    KeyProperties.ENCRYPTION_PADDING_PKCS7;

    private static final String KEY_ALIAS_AES = "MyAesKeyAlias";
    private static final String TAG_FINGERPRINT_DIALOG = "FingerprintDialog";
    private static final String DELIMITER = "]";

    private static final int REQUEST_CODE_CONFIRM_CREDENTIALS_ENCRYPT = 10;
    private static final int REQUEST_CODE_CONFIRM_CREDENTIALS_DECRYPT = 20;

    @BindView(R.id.textViewSuccess)
    protected TextView mTextCreateSuccess;

    @BindView(R.id.editTextInputOutput)
    protected EditText mEditTextInput;

    @BindView(R.id.radioAuthTimespan)
    protected RadioButton mRadioUserAuthentication;

    @BindView(R.id.radioAuthFingerprint)
    protected RadioButton mRadioUserFingerprint;

    @BindView(R.id.cardKeystore)
    protected CardView mKeystoreCard;

    private KeyguardManager mKeyguardManager;
    private FingerprintManager mFingerprintManager;
    private FingerprintDialog mFingerprintDialog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mKeyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
        mFingerprintManager = (FingerprintManager) getSystemService(Context.FINGERPRINT_SERVICE);
        mFingerprintDialog = FingerprintDialog.newInstance();

        setContentView(R.layout.activity_main);
        ButterKnife.bind(this);
    }

    @OnClick(R.id.buttonCreateKey)
    void onCreateKeyButtonClick() {
        generateAesKey();
    }

    @OnClick(R.id.buttonSymmetricEncrypt)
    void onEncryptButtonClick() {
        encryptWithAes(null);
    }

    @OnClick(R.id.buttonSymmetricDecrypt)
    void onDecryptButtonClick() {
        decryptWithAes(null);
    }

    /**
     * Generates a new AES key and stores it under the { @code KEY_ALIAS_AES } in the
     * Android Keystore.
     */
    @SuppressWarnings("StatementWithEmptyBody")
    private void generateAesKey() {
        try {
            // The KeyGenerator is an engine class for creating symmetric keys utilizing the
            // algorithm it was initialized with.
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE_PROVIDER);

            // Create a new instance of the KeyGenParameterSpec.Builder, hand over
            // the key alias and the different purposes for which you want to use the key.
            // Keep in mind that you can only use the key for the operations you have specified
            // here - once the key is created it can't be changed.
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS_AES,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);

            // Define the basic encryption parameters for the key. The set configuration
            // matches the AES_DEFAULT_TRANSFORMATION constant.
            builder.setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setKeySize(256)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);

            if (mRadioUserAuthentication.isChecked()) {
                // Create a key which requires the user to be authenticated during
                // the last 30 seconds. Could also be 30 seconds or even 5 minutes -
                // choose whatever fits your security guidelines best.
                // Before continuing, check if the user has set up a secure lockscreen -
                // if not, prompt the user to set one up ;-)
                if (!hasSetupSecureLockscreen()) return;

                builder.setUserAuthenticationRequired(true)
                        .setUserAuthenticationValidityDurationSeconds(15);
            } else if (mRadioUserFingerprint.isChecked()) {
                // Create a key which needs fingerprint authentication every time.
                // Before continuing, check if the device supports fingerprint
                // authentication and if the user has at least enrolled one fingerprint -
                // if not, prompt the user to enroll one ;-)
                if (!hasSetupFingerprint()) return;

                builder.setUserAuthenticationRequired(true);
            } else {
                // Create a key which does not need any user authentication.
                // Nothing more to add here!
            }

            // Initialize the KeyGenerator with the KeyGenParameterSpec which will be created by
            // the KeyGenParameterSpec.Builder .
            keyGenerator.init(builder.build());

            // Finally, generate the key...
            keyGenerator.generateKey();

            // ...and show a TextView with a confirmation text.
            showSuccessTextView();
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Failed to create a symmetric key", e);
        }
    }

    /**
     * Uses the key generated in { @code generateAesKey() } to encrypt the text
     * from an EditText view.
     *
     * @param cipher should be null. It's not null when called from { @code onFingerprintSuccess() }
     */
    private void encryptWithAes(@Nullable Cipher cipher) {
        String plainText = mEditTextInput.getText().toString();

        try {
            // Get a KeyStore instance with the Android Keystore provider.
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);

            // Relict of the old JCA API - you have to call load() even
            // if you do not have an input stream you want to load - otherwise it'll crash.
            keyStore.load(null);

            // Check if a generated key exists under the KEY_ALIAS_AES .
            if (!keyStore.containsAlias(KEY_ALIAS_AES)) {
                Toast.makeText(this, R.string.key_alias_not_found, Toast.LENGTH_LONG).show();
                return;
            }

            // In normal cases, the cipher object should be null and we initialize a new one.
            // When the cipher is not null, this method was called from the onFingerprintSuccess()
            // method of the FingerprintDialogCallbacks.
            if (cipher == null) {
                // Get the SecretKey from the KeyStore and instantiate a Cipher with the
                // same params we used to create the key in generateAesKey() .
                SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_ALIAS_AES, null);
                cipher = Cipher.getInstance(AES_DEFAULT_TRANSFORMATION);

                // Use the secretKey to initialize the Cipher in encryption mode.
                // If the key requires user authentication during a specific time span (specified
                // via setUserAuthenticationValidityDurationSeconds()), it may throw the
                // UserNotAuthenticatedException and we need to prompt the user
                // to authenticate again.
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);

                // Retrieve information about the SecretKey from the KeyStore.
                SecretKeyFactory factory = SecretKeyFactory.getInstance(
                        secretKey.getAlgorithm(), ANDROID_KEYSTORE_PROVIDER);
                KeyInfo info = (KeyInfo) factory.getKeySpec(secretKey, KeyInfo.class);

                // Check if the user needs to authenticate every time via fingerprint.
                if (info.isUserAuthenticationRequired() &&
                        info.getUserAuthenticationValidityDurationSeconds() == -1) {
                    // It looks like the key needs authentication every time.
                    // Show the fingerprint dialog and when the user authenticated successful,
                    // the onFingerprintSuccess() method will be called. From there this
                    // method gets called again with the initialized Cipher object.
                    showFingerprintDialog(cipher, FingerprintDialog.PURPOSE_ENCRYPT);
                    return;
                }
            }

            // The cipher is now fully initialized and ready to go - let's encrypt the
            // plainText bytes.
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

            // Encode the initialization vector (IV) and encryptedBytes to Base64.
            String base64IV = Base64.encodeToString(cipher.getIV(), Base64.DEFAULT);
            String base64Cipher = Base64.encodeToString(encryptedBytes, Base64.DEFAULT);

            // Concatenate the IV and encryptedBytes strings divided by a delimiter
            // so the result can be stored in a single string.
            String result = base64IV + DELIMITER + base64Cipher;

            // Set the visibility of the mEditTextInput view to gone so it gets animated when
            // it reappears - thanks to animateLayoutChanges="true" .
            mEditTextInput.setVisibility(View.GONE);

            // Display the result inside the mEditTextInput view.
            mEditTextInput.setText(result);
        } catch (UserNotAuthenticatedException e) {
            // The user has not authenticated within the specified timeframe, let's authenticate
            // with device credentials and try again.
            showAuthenticationScreen(REQUEST_CODE_CONFIRM_CREDENTIALS_ENCRYPT);
        } catch (KeyPermanentlyInvalidatedException e) {
            // This happens if the generated key needs user authentication and the lock screen
            // has been disabled or reset. The same applies for enrolled fingerprints.
            Toast.makeText(this, R.string.key_invalidated_msg, Toast.LENGTH_LONG).show();
        } catch (BadPaddingException | KeyStoreException | UnrecoverableKeyException |
                NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException |
                NoSuchProviderException | InvalidKeySpecException | IllegalBlockSizeException |
                CertificateException | IOException e) {
            // When developing a real world app you should handle these exceptions correctly ;-)
            throw new RuntimeException(e);
        } finally {
            // Finally make the mEditTextInput view visible again.
            mEditTextInput.setVisibility(View.VISIBLE);
        }
    }

    /**
     * Uses the key generated in { @code generateAesKey() } to decrypt the text
     * from an EditText view.
     *
     * @param cipher should be null. It's not null when called from { @code onFingerprintSuccess() }
     */
    private void decryptWithAes(@Nullable Cipher cipher) {
        String cipherText = mEditTextInput.getText().toString();

        // Split the input string and check if it consists of two parts, the Base 64 encoded
        // IV and cipher text.
        String[] inputs = cipherText.split(DELIMITER);
        if (inputs.length < 2) {
            Toast.makeText(this, R.string.corrupt_data_msg, Toast.LENGTH_SHORT).show();
            return;
        }

        try {
            // Decode the initialization vector (IV) and encryptedBytes.
            byte[] iv = Base64.decode(inputs[0], Base64.DEFAULT);
            byte[] cipherBytes = Base64.decode(inputs[1], Base64.DEFAULT);

            // Get a KeyStore instance with the Android Keystore provider.
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);

            // Relict of the old JCA API - you have to call load() even
            // if you do not have an input stream you want to load - otherwise it'll crash.
            keyStore.load(null);

            // Check if a generated key exists under the KEY_ALIAS_AES .
            if (!keyStore.containsAlias(KEY_ALIAS_AES)) {
                Toast.makeText(this, R.string.key_alias_not_found, Toast.LENGTH_LONG).show();
                return;
            }

            // In normal cases, the cipher object should be null and we initialize a new one.
            // When the cipher is not null, this method was called from the onFingerprintSuccess()
            // method of the FingerprintDialogCallbacks.
            if (cipher == null) {
                // Get the SecretKey from the KeyStore and instantiate a Cipher with the
                // same params we used to create the key in generateAesKey() .
                SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_ALIAS_AES, null);
                cipher = Cipher.getInstance(AES_DEFAULT_TRANSFORMATION);

                // Use the secretKey to initialize the Cipher in decryption mode.
                // If the key requires user authentication during a specific time span (specified
                // via setUserAuthenticationValidityDurationSeconds()), it may throw the
                // UserNotAuthenticatedException and we need to prompt the user
                // to authenticate again.
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

                // Retrieve information about the SecretKey from the KeyStore.
                SecretKeyFactory factory = SecretKeyFactory.getInstance(
                        secretKey.getAlgorithm(), ANDROID_KEYSTORE_PROVIDER);
                KeyInfo info = (KeyInfo) factory.getKeySpec(secretKey, KeyInfo.class);

                // Check if the user needs to authenticate every time via fingerprint.
                if (info.isUserAuthenticationRequired() &&
                        info.getUserAuthenticationValidityDurationSeconds() == -1) {
                    // It looks like the key needs authentication every time.
                    // Show the fingerprint dialog and when the user authenticated successful,
                    // the onFingerprintSuccess() method will be called. From there this
                    // method gets called again with the initialized Cipher object.
                    showFingerprintDialog(cipher, FingerprintDialog.PURPOSE_DECRYPT);
                    return;
                }
            }

            // The cipher is now fully initialized and ready to go - let's decrypt the
            // cipherBytes.
            byte[] decryptedBytes = cipher.doFinal(cipherBytes);

            // Set the visibility of the mEditTextInput view to gone so it gets animated when
            // it reappears - thanks to animateLayoutChanges="true" .
            mEditTextInput.setVisibility(View.GONE);

            // Display the result inside the mEditTextInput view.
            mEditTextInput.setText(new String(decryptedBytes));
        } catch (UserNotAuthenticatedException e) {
            // The user has not authenticated within the specified timeframe, let's authenticate
            // with device credentials and try again.
            showAuthenticationScreen(REQUEST_CODE_CONFIRM_CREDENTIALS_DECRYPT);
        } catch (KeyPermanentlyInvalidatedException e) {
            // This happens if the generated key needs user authentication and the lock screen
            // has been disabled or reset. The same applies for enrolled fingerprints.
            Toast.makeText(this, R.string.key_invalidated_msg, Toast.LENGTH_LONG).show();
        } catch (IllegalBlockSizeException | BadPaddingException | IllegalArgumentException e) {
            // Catch invalid inputs
            Toast.makeText(this, R.string.corrupt_data_msg, Toast.LENGTH_SHORT).show();
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchPaddingException |
                NoSuchAlgorithmException | InvalidKeyException | CertificateException |
                NoSuchProviderException | InvalidKeySpecException |
                IOException | InvalidAlgorithmParameterException e) {
            // When developing a real world app you should handle these exceptions correctly ;-)
            throw new RuntimeException(e);
        } finally {
            // Finally make the mEditTextInput view visible again.
            mEditTextInput.setVisibility(View.VISIBLE);
        }
    }

    /**
     * Shows a TextView which contains a confirmation that the key was successfully created
     * and uses an awesome animation to catch the users attention. Weeee!
     */
    private void showSuccessTextView() {
        mTextCreateSuccess.setVisibility(View.VISIBLE);
        mTextCreateSuccess.setScaleX(0);
        mTextCreateSuccess.setScaleY(0);
        mTextCreateSuccess.animate()
                .scaleX(1)
                .scaleY(1)
                .setInterpolator(new OvershootInterpolator(1.4f));
    }

    /**
     * Checks whether the user has set up a secure lock screen.
     *
     * @return true if the user has set up a secure lock screen
     */
    private boolean hasSetupSecureLockscreen() {
        if (!mKeyguardManager.isKeyguardSecure()) {
            // Show a message that the user hasn't set up a lock screen.
            Toast.makeText(this, R.string.setup_lockscreen_msg, Toast.LENGTH_LONG).show();
            return false;
        }

        return true;
    }

    /**
     * Checks whether the device supports fingerprint authentication and if the user has
     * enrolled at least one fingerprint.
     *
     * @return true if the user has a fingerprint capable device and has enrolled
     * one or more fingerprints
     */
    private boolean hasSetupFingerprint() {
        try {
            if (!mFingerprintManager.isHardwareDetected()) {
                Toast.makeText(this,
                        R.string.fingerprint_missing_hardware, Toast.LENGTH_LONG).show();
                return false;
            } else if (!mFingerprintManager.hasEnrolledFingerprints()) {
                Toast.makeText(this,
                        R.string.fingerprint_not_enrolled, Toast.LENGTH_LONG).show();
                return false;
            }
        } catch (SecurityException e) {
            // Should never be thrown since we have declared the USE_FINGERPRINT permission
            // in the manifest file
            return false;
        }

        return true;
    }

    /**
     * Dispatches the confirm credential intent to authenticate the user.
     *
     * @param requestCode represents the action we want to do after a successful authentication
     */
    private void showAuthenticationScreen(int requestCode) {
        // Create the Confirm Credentials screen. You can customize the title and description.
        // Or it will provide a generic one for you if you leave the arguments to null.
        Intent intent = mKeyguardManager.createConfirmDeviceCredentialIntent(
                getString(R.string.confirm_credential_title),
                getString(R.string.confirm_credential_msg));
        if (intent != null) {
            startActivityForResult(intent, requestCode);
        }
    }

    /**
     * Shows a { @code FingerprintDialog } .
     *
     * @param cipher             which needs user authentication
     * @param fingerprintPurpose represents the purpose e.g. ENCRYPT, DECRYPT
     */
    private void showFingerprintDialog(Cipher cipher, int fingerprintPurpose) {
        if (getFragmentManager().findFragmentByTag(TAG_FINGERPRINT_DIALOG) == null) {
            mFingerprintDialog.init(fingerprintPurpose,
                    new FingerprintManager.CryptoObject(cipher));
            mFingerprintDialog.show(getFragmentManager(), TAG_FINGERPRINT_DIALOG);
        }
    }

    /**
     * Receives the results from the activity launched by the ConfirmDeviceCredentialIntent.
     */
    @SuppressWarnings("StatementWithEmptyBody")
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == RESULT_OK) {
            // The user authenticated successfully, so let's try to en-/decrypt again.
            if (requestCode == REQUEST_CODE_CONFIRM_CREDENTIALS_ENCRYPT) {
                encryptWithAes(null);
            } else if (requestCode == REQUEST_CODE_CONFIRM_CREDENTIALS_DECRYPT) {
                decryptWithAes(null);
            }
        } else {
            // The user canceled or didn’t complete the lock screen
            // operation. Go to error/cancellation flow.
        }
    }


    /**
     * Gets called by the { @code FingerprintDialog } when the user successfully
     * authenticated via fingerprint.
     *
     * @param purpose      represents the purpose, e.g. PURPOSE_ENCRYPT or PURPOSE_DECRYPT
     * @param cryptoObject contains the cipher object
     */
    @Override
    public void onFingerprintSuccess(int purpose, FingerprintManager.CryptoObject cryptoObject) {
        switch (purpose) {
            case FingerprintDialog.PURPOSE_ENCRYPT:
                // Let's try to encrypt again with the pre-initialized Cipher object
                encryptWithAes(cryptoObject.getCipher());
                break;
            case FingerprintDialog.PURPOSE_DECRYPT:
                // Let's try to decrypt again with the pre-initialized Cipher object
                decryptWithAes(cryptoObject.getCipher());
                break;
        }
    }

    /**
     * Gets called by the { @code FingerprintDialog } when the user clicked the cancel
     * button inside the dialog.
     */
    @Override
    public void onFingerprintCancel() {
        // The user canceled or didn’t complete the fingerprint
        // operation. Go to error/cancellation flow.
    }
}
