package conf

import (
	"github.com/xtls/xray-core/app/policy"
)

// PolicyLimits is "limits" of a policy level: the limits of the new
// connections of each of its users (fork: common/connlimit, FORK.md). A
// number left out or zero turns its limit off.
type PolicyLimits struct {
	Connections  uint32   `json:"connections"`
	Rate         uint32   `json:"rate"`
	Burst        uint32   `json:"burst"`
	FailedRate   uint32   `json:"failedRate"`
	FailedBurst  uint32   `json:"failedBurst"`
	UDPSessions  uint32   `json:"udpSessions"`
	UDPRate      uint32   `json:"udpRate"`
	UDPBurst     uint32   `json:"udpBurst"`
	UDPLive      uint32   `json:"udpLive"`
	LookupRate   uint32   `json:"lookupRate"`
	LookupBurst  uint32   `json:"lookupBurst"`
	FoldSuffixes []string `json:"foldSuffixes"`
	FoldAt       string   `json:"foldAt"`
}

// Build is the limits of the level, nil without "limits".
func (l *PolicyLimits) Build() *policy.Policy_Limits {
	if l == nil {
		return nil
	}
	return &policy.Policy_Limits{
		Connections:  l.Connections,
		Rate:         l.Rate,
		Burst:        l.Burst,
		FailedRate:   l.FailedRate,
		FailedBurst:  l.FailedBurst,
		UdpSessions:  l.UDPSessions,
		UdpRate:      l.UDPRate,
		UdpBurst:     l.UDPBurst,
		UdpLive:      l.UDPLive,
		LookupRate:   l.LookupRate,
		LookupBurst:  l.LookupBurst,
		FoldSuffixes: l.FoldSuffixes,
		FoldAt:       l.FoldAt,
	}
}
