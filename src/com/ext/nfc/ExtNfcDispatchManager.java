package com.ext.nfc;

import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.Tag;
import android.os.Bundle;
import android.os.UserHandle;
import android.util.Log;

import com.android.nfc.NfcService;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

/**
 * External NFC Dispatch Manager 
 * Ported from Flyme
 */
public class ExtNfcDispatchManager {
    private static final String TAG = "ExtNfcDispatchManager";
    private static final boolean DBG = true;

    private final Context mContext;
    private final BroadcastReceiver mReceiver;
    private TagRules mTagRules;
    private final HashMap<String, ComponentName> mComponentMap = new HashMap<>();

    static class TagRules {
        List<TagRuleGroup> ruleGroups = new ArrayList<>();
    }

    static class TagRuleGroup {
        String ruleType;
        List<TagRule> rules = new ArrayList<>();
    }

    static class TagRule {
        String recordType;
        String record;
        List<String> components = new ArrayList<>();
        String description;
    }

    public ExtNfcDispatchManager(Context context) {
        mContext = context;
        loadRules(context);

        mReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                String action = intent.getAction();
                if (action == null) return;

                if (action.equals(Intent.ACTION_PACKAGE_ADDED) ||
                    action.equals(Intent.ACTION_PACKAGE_CHANGED) ||
                    action.equals(Intent.ACTION_PACKAGE_REMOVED)) {
                    if (DBG) Log.d(TAG, "Package changed, regenerating component map.");
                    generateComponentMap(context);
                }
            }
        };

        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(Intent.ACTION_PACKAGE_ADDED);
        intentFilter.addAction(Intent.ACTION_PACKAGE_CHANGED);
        intentFilter.addAction(Intent.ACTION_PACKAGE_REMOVED);
        intentFilter.addDataScheme("package");
        context.registerReceiverAsUser(mReceiver, UserHandle.ALL, intentFilter, null, null);
    }

    private void loadRules(Context context) {
        try {
            String jsonString = readAssetFile(context, "rules.json");
            if (jsonString.isEmpty()) {
                Log.e(TAG, "rules.json is empty or could not be read.");
                return;
            }

            mTagRules = new TagRules();
            JSONObject root = new JSONObject(jsonString);
            JSONArray ruleGroupsArray = root.getJSONArray("rule_group");

            for (int i = 0; i < ruleGroupsArray.length(); i++) {
                JSONObject groupObject = ruleGroupsArray.getJSONObject(i);
                TagRuleGroup group = new TagRuleGroup();
                group.ruleType = groupObject.getString("rule_type");

                JSONArray rulesArray = groupObject.getJSONArray("rules");
                for (int j = 0; j < rulesArray.length(); j++) {
                    JSONObject ruleObject = rulesArray.getJSONObject(j);
                    TagRule rule = new TagRule();
                    rule.recordType = ruleObject.optString("record_type", "");
                    rule.record = ruleObject.optString("record", "");
                    rule.description = ruleObject.optString("description", "");

                    JSONArray componentsArray = ruleObject.getJSONArray("components");
                    for (int k = 0; k < componentsArray.length(); k++) {
                        rule.components.add(componentsArray.getString(k));
                    }
                    group.rules.add(rule);
                }
                mTagRules.ruleGroups.add(group);
            }

            generateComponentMap(context);
            if (DBG) Log.d(TAG, "Tag rules loaded successfully");

        } catch (IOException | JSONException e) {
            Log.e(TAG, "Error loading or parsing NFC dispatch rules", e);
            mTagRules = null; // Ensure rules are null on failure
        }
    }


    private void generateComponentMap(Context context) {
        mComponentMap.clear();
        if (mTagRules == null || mTagRules.ruleGroups == null) {
            return;
        }

        PackageManager packageManager = context.getPackageManager();
        for (TagRuleGroup group : mTagRules.ruleGroups) {
            if (group.rules == null) continue;
            for (TagRule rule : group.rules) {
                if (rule.components == null) continue;
                for (String componentStr : rule.components) {
                    ComponentName componentName = ComponentName.unflattenFromString(componentStr);
                    if (componentName == null) continue;
                    try {
                        ActivityInfo activityInfo = packageManager.getActivityInfo(componentName, 0);
                        if (activityInfo != null && activityInfo.exported) {
                            mComponentMap.put(componentStr, componentName);
                        }
                    } catch (PackageManager.NameNotFoundException e) {
                    
                    }
                }
            }
        }
        if (DBG) {
            Log.d(TAG, "Generated component map: " + mComponentMap);
        }
    }

    public boolean match(Tag tag, NdefMessage ndefMessage, Bundle bundle) {
        if (ndefMessage == null || mTagRules == null) {
            return false;
        }

        for (TagRuleGroup group : mTagRules.ruleGroups) {
            if ("NDEF".equals(group.ruleType)) {
                if (matchNdefRecords(ndefMessage.getRecords(), group.rules, bundle)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean matchNdefRecords(NdefRecord[] records, List<TagRule> rules, Bundle bundle) {
        for (NdefRecord record : records) {
            for (TagRule rule : rules) {
                // Match Android Application Record (AAR)
                if (record.getTnf() == NdefRecord.TNF_EXTERNAL_TYPE &&
                    Arrays.equals(record.getType(), NdefRecord.RTD_ANDROID_APP)) {
                    String pkgName = new String(record.getPayload(), StandardCharsets.US_ASCII);
                    if (pkgName.equals(rule.record)) {
                        bundle.putStringArrayList("components", (ArrayList<String>) rule.components);
                        if (DBG) Log.d(TAG, "Matched AAR for package: " + pkgName);
                        return true;
                    }
                }

                // Match MIME Type record with regex on payload
                if (record.getTnf() == NdefRecord.TNF_MIME_MEDIA) {
                    String mimeType = record.toMimeType();
                    if (rule.recordType.equals(mimeType)) {
                        String payloadStr = new String(record.getPayload(), StandardCharsets.UTF_8);
                        if (Pattern.matches(rule.record, payloadStr)) {
                           bundle.putStringArrayList("components", (ArrayList<String>) rule.components);
                           if (DBG) Log.d(TAG, "Matched MIME type '" + mimeType + "' with payload pattern.");
                           return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    public boolean tryDirectDispatch(Intent intent, Bundle bundle) {
        ArrayList<String> componentStrings = bundle.getStringArrayList("components");
        if (componentStrings == null || componentStrings.isEmpty()) {
            return false;
        }

        ArrayList<ComponentName> validComponents = new ArrayList<>();
        filterMatchedComponents(componentStrings, validComponents);

        if (validComponents.isEmpty()) {
            if (DBG) Log.d(TAG, "No valid (installed and exported) components found for this tag.");
            return false;
        }

        ComponentName componentToDispatch = validComponents.get(0);
        intent.setComponent(componentToDispatch);

        try {
            mContext.startActivityAsUser(intent, UserHandle.CURRENT);
            if (DBG) Log.d(TAG, "Successfully dispatched to component: " + componentToDispatch.flattenToString());
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to start activity for component: " + componentToDispatch.flattenToString(), e);
            return false;
        }
    }

    private void filterMatchedComponents(List<String> componentStrings, List<ComponentName> validComponents) {
        for (String str : componentStrings) {
            ComponentName componentName = mComponentMap.get(str);
            if (componentName != null) {
                validComponents.add(componentName);
            }
        }
    }

    private String readAssetFile(Context context, String fileName) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (InputStream is = context.getAssets().open(fileName);
             BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        }
        return sb.toString();
    }
}