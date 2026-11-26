package kiro

import "testing"

func TestNormalizeUsageLimits(t *testing.T) {
	raw := []byte(`{
	  "subscriptionInfo": {"subscriptionTitle": "KIRO PRO"},
	  "nextDateReset": 1798761600,
	  "usageBreakdownList": [{
	    "resourceType": "CREDIT", "displayName": "Credits",
	    "currentUsage": 12, "currentUsageWithPrecision": 12.5, "usageLimit": 50, "usageLimitWithPrecision": 50,
	    "bonuses": [
	      {"displayName": "Welcome", "status": "ACTIVE", "currentUsage": 10, "usageLimit": 100, "expiresAt": 1798761600},
	      {"displayName": "Old", "status": "EXPIRED", "currentUsage": 1, "usageLimit": 5}
	    ],
	    "freeTrialInfo": {"freeTrialStatus": "EXPIRED", "currentUsage": 1, "usageLimit": 500}
	  }]
	}`)
	resp, err := normalizeUsageLimits(raw)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Subscription == nil || resp.Subscription.Plan != "PRO" {
		t.Fatalf("plan: %+v", resp.Subscription)
	}
	buckets := resp.Groups[0].Buckets
	if len(buckets) != 2 {
		t.Fatalf("want main + active bonus, got %+v", buckets)
	}
	if buckets[0].Window != "Credits" || buckets[0].RemainingFraction != 0.75 ||
		buckets[0].ResetTime != "2027-01-01T00:00:00Z" || buckets[0].Description != "12.5 / 50 used" {
		t.Fatalf("main bucket: %+v", buckets[0])
	}
	if buckets[1].Window != "Bonus: Welcome" || buckets[1].RemainingFraction != 0.9 {
		t.Fatalf("bonus bucket: %+v", buckets[1])
	}
	if resp.Summary[0].Value != 22.5 || resp.Summary[1].Value != 150 {
		t.Fatalf("summary: %+v", resp.Summary)
	}
	if _, err := normalizeUsageLimits([]byte(`{}`)); err == nil {
		t.Fatal("empty usage must error")
	}
}
