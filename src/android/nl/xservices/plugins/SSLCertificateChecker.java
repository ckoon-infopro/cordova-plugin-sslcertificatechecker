package nl.xservices.plugins;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;

import javax.net.ssl.HttpsURLConnection;

import javax.security.cert.CertificateException;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import android.util.Log;

public class SSLCertificateChecker extends CordovaPlugin {

  private static final String ACTION_CHECK_EVENT = "check";
  private static char[] HEX_CHARS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
  public static final int MAX_RETRIES = 3;
  public static final int TIMEOUT = 30000;

  @Override
  public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext)
      throws JSONException {
    if (ACTION_CHECK_EVENT.equals(action)) {
      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
          try {
            final String serverURL = args.getString(0);
            final JSONArray allowedFingerprints = args.getJSONArray(2);
            final String serverCertFingerprint = getFingerprint(serverURL);
            for (int j = 0; j < allowedFingerprints.length(); j++) {
              if (allowedFingerprints.get(j).toString().equalsIgnoreCase(serverCertFingerprint)) {
                callbackContext.success("CONNECTION_SECURE");
                return;
              }
            }
            callbackContext.error("CONNECTION_NOT_SECURE");
          } catch (Exception e) {
            e.printStackTrace();
            callbackContext.error("CONNECTION_NOT_SECURE");
            // callbackContext.error("CONNECTION_FAILED. Details: " + e.getMessage());
          }
        }
      });
      return true;
    } else {
      callbackContext.error("sslCertificateChecker." + action + " is not a supported function. Did you mean '"
          + ACTION_CHECK_EVENT + "'?");
      return false;
    }
  }

  private static String getFingerprint(String httpsURL)
      throws IOException, NoSuchAlgorithmException, CertificateException, CertificateEncodingException {
    Log.d("SSLCertificateChecker", "httpsURL: " + httpsURL);

    String fingerprint = null;

    HttpsURLConnection con = null;

    boolean hasTimeout = true;
    int retries = 0;

    while (hasTimeout && retries < MAX_RETRIES) {
      try {
        con = (HttpsURLConnection) new URL(httpsURL).openConnection();
        con.setConnectTimeout(TIMEOUT);
        con.setReadTimeout(TIMEOUT);
        con.connect();

        final Certificate cert = con.getServerCertificates()[0];
        final MessageDigest md = MessageDigest.getInstance("SHA256");
        md.update(cert.getEncoded());
        fingerprint = dumpHex(md.digest());

        hasTimeout = false;

      } catch (SocketTimeoutException e) {
        retries++;
        Log.e("SocketTimeoutException", "Retrying: " + retries);
        if (retries == MAX_RETRIES) {
          throw e;
        }
      } finally {
        con.disconnect();
      }
    }

    return fingerprint;
  }

  private static String dumpHex(byte[] data) {
    final int n = data.length;
    final StringBuilder sb = new StringBuilder(n * 3 - 1);
    for (int i = 0; i < n; i++) {
      if (i > 0) {
        sb.append(' ');
      }
      sb.append(HEX_CHARS[(data[i] >> 4) & 0x0F]);
      sb.append(HEX_CHARS[data[i] & 0x0F]);
    }
    return sb.toString();
  }
}
