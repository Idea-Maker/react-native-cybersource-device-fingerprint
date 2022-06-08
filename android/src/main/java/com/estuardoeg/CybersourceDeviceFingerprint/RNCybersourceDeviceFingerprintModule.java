
package com.estuardoeg.CybersourceDeviceFingerprint;

import android.app.Application;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;
import com.threatmetrix.TrustDefender.TMXProfiling;
import com.threatmetrix.TrustDefender.TMXConfig;
import com.threatmetrix.TrustDefender.TMXStatusCode;
import com.threatmetrix.TrustDefender.TMXProfilingOptions;
import com.threatmetrix.TrustDefender.TMXEndNotifier;
import com.threatmetrix.TrustDefender.TMXProfilingHandle.Result;

import java.util.ArrayList;
import java.util.List;


public class RNCybersourceDeviceFingerprintModule extends ReactContextBaseJavaModule {

    private static final String CYBERSOURCE_SDK = "RNCybersourceDeviceFingerprint";
    private final Application _application;
    private TMXProfiling _defender = null;

    public RNCybersourceDeviceFingerprintModule(ReactApplicationContext reactContext, Application application) {
        super(reactContext);
        _application = application;
    }

    @Override
    public String getName() {
        return CYBERSOURCE_SDK;
    }

    @ReactMethod
    public void configure(final String orgId, final String serverURL, final Promise promise) {
        if (_defender != null) {
            promise.reject(CYBERSOURCE_SDK, "CyberSource SDK já foi iniciado.");
            return;
        }

        _defender = TMXProfiling.getInstance();

        try {
            TMXConfig config = new TMXConfig()
                    .setOrgId(orgId)
                    .setFPServer(serverURL)
                    .setContext(_application);

            _defender.init(config);
        } catch (IllegalArgumentException exception) {
            promise.reject(CYBERSOURCE_SDK, "Parâmetros inválidos");
        }

        promise.resolve(true);
    }

    @ReactMethod
    public void getSessionID(final String fingerprintKey, final Promise promise) {
        if (_defender == null) {
            promise.reject(CYBERSOURCE_SDK, "CyberSource SDK não foi inicializado");
            return;
        }

        TMXProfilingOptions options = new TMXProfilingOptions();

        options.setCustomAttributes(null);
        options.setSessionID(fingerprintKey);

        TMXProfiling.getInstance().profile(options, new CompletionNotifier(promise));
    }

    private class CompletionNotifier implements TMXEndNotifier {
        private final Promise _promise;

        CompletionNotifier(Promise promise) {
            super();
            _promise = promise;
        }

        @Override
        public void complete(Result result) {
            WritableMap map = new WritableNativeMap();
            map.putString("sessionId", result.getSessionID());
            map.putInt("status", result.getStatus().ordinal());
            _promise.resolve(map);
        }
    }
}
