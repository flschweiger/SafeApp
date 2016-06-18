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

import android.animation.Animator;
import android.app.DialogFragment;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.support.annotation.Nullable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.OvershootInterpolator;
import android.widget.ImageView;
import android.widget.TextView;

import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.OnClick;

public class FingerprintDialog extends DialogFragment {

    public static final int PURPOSE_ENCRYPT = 1;
    public static final int PURPOSE_DECRYPT = 2;
    public static final int ANIMATION_DURATION = 500;

    @BindView(R.id.textViewFingerprintStatus)
    protected TextView mTextViewStatus;

    @BindView(R.id.imageViewFingerprintStatus)
    protected ImageView mImageViewStatus;

    private FingerprintManager mFingerprintManager;
    private CancellationSignal mCancellationSignal;
    private FingerprintManager.CryptoObject mCryptoObject;
    private FingerprintDialogCallbacks mCallbacks;
    private Context mContext;
    private int mPurpose;

    public FingerprintDialog() {
        // Empty constructor
    }

    public static FingerprintDialog newInstance() {
        return new FingerprintDialog();
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Do not create a new Fragment when the Activity is re-created such as orientation changes.
        setRetainInstance(true);

        mContext = getActivity().getApplicationContext();
        mFingerprintManager = (FingerprintManager)
                mContext.getSystemService(Context.FINGERPRINT_SERVICE);
        mCallbacks = (FingerprintDialogCallbacks) getActivity();
    }

    @Override
    public void onResume() {
        super.onResume();
        // Reset the cancellation signal which is used to cancel the
        // fingerprint authentication process.
        mCancellationSignal = new CancellationSignal();

        // Check if a valid CryptoObject has been provided
        if (mCryptoObject != null) {
            try {
                // Start listening for fingerprint events
                mFingerprintManager.authenticate(mCryptoObject, mCancellationSignal,
                        0, new AuthCallbacks(), null);
            } catch (IllegalArgumentException | IllegalStateException | SecurityException e) {
                // Should never be thrown since we have declared the USE_FINGERPRINT permission
                // in the manifest
            }
        }
    }

    @Override
    public void onPause() {
        super.onPause();

        // If the fingerprint authentication process is running, cancel it.
        mCancellationSignal.cancel();
    }

    @Nullable
    @Override
    public View onCreateView(LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {
        View content = inflater.inflate(R.layout.fragment_fingerprint, container);
        ButterKnife.bind(this, content);

        getDialog().setTitle(R.string.fingerprint_dialog_title);

        return content;
    }

    @OnClick(R.id.buttonFingerprintCancel)
    protected void onCancelPressed() {
        mCallbacks.onFingerprintCancel();
        dismiss();
    }

    /**
     * Should be called before the dialog is shown in order to provide a valid CryptoObject.
     *
     * @param purpose The purpose for which you want to use the CryptoObject
     * @param object  The CryptoObject we want to authenticate for
     */
    public void init(int purpose, FingerprintManager.CryptoObject object) {
        mCryptoObject = object;
        mPurpose = purpose;
    }

    /**
     * Updates the status text in the dialog with the provided error message.
     *
     * @param text represents the error message which will be shown
     */
    private void showErrorText(CharSequence text) {
        mImageViewStatus.setImageResource(R.drawable.ic_fingerprint_error);
        mTextViewStatus.setText(text);
        mTextViewStatus.setTextColor(mContext.getColor(R.color.red));

        mImageViewStatus.animate()
                .rotationBy(90)
                .setInterpolator(new OvershootInterpolator(1.4f))
                .setDuration(ANIMATION_DURATION);
    }

    /**
     * Updates the status text in the dialog with a success text.
     */
    private void showSuccessText() {
        mImageViewStatus.setImageResource(R.drawable.ic_fingerprint_done);
        mTextViewStatus.setText(getString(R.string.fingerprint_auth_success));
        mTextViewStatus.setTextColor(mContext.getColor(R.color.green));

        mImageViewStatus.setRotation(60);
        mImageViewStatus.animate()
                .rotation(0)
                .setInterpolator(new DecelerateInterpolator(1.4f))
                .setDuration(ANIMATION_DURATION)
                .setListener(new Animator.AnimatorListener() {
                    @Override
                    public void onAnimationStart(Animator animation) {
                        // Empty
                    }

                    @Override
                    public void onAnimationEnd(Animator animation) {
                        // Wait for the animation to finish, then dismiss the dialog and
                        // invoke the callback method
                        mCallbacks.onFingerprintSuccess(mPurpose, mCryptoObject);
                        dismiss();
                    }

                    @Override
                    public void onAnimationCancel(Animator animation) {
                        // Empty
                    }

                    @Override
                    public void onAnimationRepeat(Animator animation) {
                        // Empty
                    }
                });
    }

    /**
     * The interface which the calling activity needs to implement.
     */
    public interface FingerprintDialogCallbacks {
        void onFingerprintSuccess(int purpose, FingerprintManager.CryptoObject cryptoObject);

        void onFingerprintCancel();
    }

    /**
     * This class represents the callbacks invoked by the FingerprintManager class.
     */
    class AuthCallbacks extends FingerprintManager.AuthenticationCallback {

        @Override
        public void onAuthenticationFailed() {
            super.onAuthenticationFailed();
            showErrorText(getString(R.string.fingerprint_auth_failed));
        }

        @Override
        public void onAuthenticationError(int errorCode, CharSequence errString) {
            super.onAuthenticationError(errorCode, errString);
            showErrorText(errString);
        }

        @Override
        public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
            super.onAuthenticationHelp(helpCode, helpString);
            showErrorText(helpString);
        }

        @Override
        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
            super.onAuthenticationSucceeded(result);
            showSuccessText();
        }
    }
}
