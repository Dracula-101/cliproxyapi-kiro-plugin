package kiro

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

type quotaFetchRequest struct {
	pluginapi.QuotaFetchRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

// usageLimits is the part of CodeWhisperer getUsageLimits the panel shows.
type usageLimits struct {
	UsageBreakdownList []usageBreakdown `json:"usageBreakdownList"`
	SubscriptionInfo   struct {
		SubscriptionTitle string `json:"subscriptionTitle"`
	} `json:"subscriptionInfo"`
	NextDateReset any `json:"nextDateReset"`
}

type usageAmounts struct {
	CurrentUsage              float64  `json:"currentUsage"`
	CurrentUsageWithPrecision *float64 `json:"currentUsageWithPrecision"`
	UsageLimit                float64  `json:"usageLimit"`
	UsageLimitWithPrecision   *float64 `json:"usageLimitWithPrecision"`
}

func (a usageAmounts) usedAndLimit() (float64, float64) {
	used, limit := a.CurrentUsage, a.UsageLimit
	if a.CurrentUsageWithPrecision != nil {
		used = *a.CurrentUsageWithPrecision
	}
	if a.UsageLimitWithPrecision != nil {
		limit = *a.UsageLimitWithPrecision
	}
	return used, limit
}

type usageBreakdown struct {
	usageAmounts
	ResourceType  string `json:"resourceType"`
	DisplayName   string `json:"displayName"`
	NextDateReset any    `json:"nextDateReset"`
	Bonuses       []struct {
		usageAmounts
		DisplayName string `json:"displayName"`
		Status      string `json:"status"`
		ExpiresAt   any    `json:"expiresAt"`
	} `json:"bonuses"`
	FreeTrialInfo *struct {
		usageAmounts
		FreeTrialStatus string `json:"freeTrialStatus"`
		FreeTrialExpiry any    `json:"freeTrialExpiry"`
	} `json:"freeTrialInfo"`
}

func fetchKiroQuota(request []byte) ([]byte, error) {
	var req quotaFetchRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	var cred kiroCredential
	if errUnmarshal := json.Unmarshal(req.StorageJSON, &cred); errUnmarshal != nil || strings.TrimSpace(cred.AccessToken) == "" {
		return wire.ErrorStatus("invalid_credential", "kiro credential has no accessToken", http.StatusUnauthorized), nil
	}
	raw, errFetch := fetchUsageLimits(req.HostCallbackID, cred)
	if errFetch != nil {
		return wire.ErrorStatus("quota_failed", errFetch.Error(), http.StatusBadGateway), nil
	}
	resp, errNormalize := normalizeUsageLimits(raw)
	if errNormalize != nil {
		return wire.ErrorStatus("quota_failed", errNormalize.Error(), http.StatusBadGateway), nil
	}
	return wire.OK(resp)
}

func normalizeUsageLimits(raw []byte) (pluginapi.QuotaFetchResponse, error) {
	var usage usageLimits
	if errUnmarshal := json.Unmarshal(raw, &usage); errUnmarshal != nil {
		return pluginapi.QuotaFetchResponse{}, fmt.Errorf("decode getUsageLimits: %w", errUnmarshal)
	}
	var buckets []pluginapi.QuotaBucket
	var totalUsed, totalLimit float64
	add := func(name string, amounts usageAmounts, reset any) {
		used, limit := amounts.usedAndLimit()
		if limit <= 0 {
			return
		}
		totalUsed += used
		totalLimit += limit
		buckets = append(buckets, pluginapi.QuotaBucket{
			Window:            name,
			RemainingFraction: math.Max(0, math.Min(1, 1-used/limit)),
			ResetTime:         kiroTimestamp(reset),
			Description:       fmt.Sprintf("%s / %s used", formatAmount(used), formatAmount(limit)),
		})
	}
	for _, b := range usage.UsageBreakdownList {
		add(firstNonEmptyStr(b.DisplayName, b.ResourceType, "Credits"), b.usageAmounts, firstNonNil(b.NextDateReset, usage.NextDateReset))
		for _, bonus := range b.Bonuses {
			if !strings.EqualFold(bonus.Status, "EXPIRED") {
				add("Bonus: "+firstNonEmptyStr(bonus.DisplayName, "credits"), bonus.usageAmounts, bonus.ExpiresAt)
			}
		}
		if ft := b.FreeTrialInfo; ft != nil && !strings.EqualFold(ft.FreeTrialStatus, "EXPIRED") {
			add("Free trial", ft.usageAmounts, ft.FreeTrialExpiry)
		}
	}
	if len(buckets) == 0 {
		return pluginapi.QuotaFetchResponse{}, fmt.Errorf("getUsageLimits returned no usage")
	}
	resp := pluginapi.QuotaFetchResponse{
		Groups: []pluginapi.QuotaGroup{{DisplayName: "Credits", Buckets: buckets}},
		Summary: []pluginapi.QuotaMetric{
			{Key: "used", Label: "Credits used", Value: round2(totalUsed), Format: "number"},
			{Key: "limit", Label: "Credit limit", Value: round2(totalLimit), Format: "number"},
		},
	}
	if plan := strings.TrimSpace(usage.SubscriptionInfo.SubscriptionTitle); plan != "" {
		resp.Subscription = &pluginapi.QuotaSubscription{Plan: strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(plan), "KIRO "))}
	}
	return resp, nil
}

// kiroTimestamp turns getUsageLimits' epoch seconds (or an ISO string) into RFC 3339.
func kiroTimestamp(value any) string {
	var seconds float64
	switch v := value.(type) {
	case float64:
		seconds = v
	case string:
		if t, ok := parseKiroTime(v); ok {
			return t.UTC().Format(time.RFC3339)
		}
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return ""
		}
		seconds = parsed
	default:
		return ""
	}
	if seconds <= 0 {
		return ""
	}
	if seconds > 1e11 {
		seconds /= 1000
	}
	return time.Unix(int64(seconds), 0).UTC().Format(time.RFC3339)
}

func firstNonNil(values ...any) any {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

func formatAmount(v float64) string { return strconv.FormatFloat(round2(v), 'f', -1, 64) }
