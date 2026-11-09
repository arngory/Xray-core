package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/app/policy"
	. "github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

// "limits" of a policy level, with the numbers raycontrol renders
// (conn-limit-v1 §5); without it the level has none.
func TestPolicyLimits(t *testing.T) {
	const text = `{
		"levels": {
			"0": {
				"statsUserUplink": true,
				"statsUserDownlink": true,
				"limits": {
					"connections": 1024,
					"rate": 30,
					"burst": 600,
					"failedRate": 5,
					"failedBurst": 100,
					"udpSessions": 256,
					"udpRate": 100,
					"udpBurst": 200,
					"udpLive": 1024,
					"lookupRate": 20,
					"lookupBurst": 100,
					"foldAt": "-"
				}
			},
			"1": {"limits": {"connections": 8, "foldSuffixes": ["-n", "-p"]}},
			"2": {"connIdle": 300}
		}
	}`
	var c PolicyConfig
	if err := json.Unmarshal([]byte(text), &c); err != nil {
		t.Fatal(err)
	}
	got, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	want := &policy.Policy_Limits{
		Connections: 1024, Rate: 30, Burst: 600, FailedRate: 5, FailedBurst: 100,
		UdpSessions: 256, UdpRate: 100, UdpBurst: 200, UdpLive: 1024, LookupRate: 20, LookupBurst: 100,
		FoldAt: "-",
	}
	if !proto.Equal(got.Level[0].Limits, want) {
		t.Errorf("level 0: %v, want %v", got.Level[0].Limits, want)
	}
	want = &policy.Policy_Limits{Connections: 8, FoldSuffixes: []string{"-n", "-p"}}
	if !proto.Equal(got.Level[1].Limits, want) {
		t.Errorf("level 1: %v, want %v", got.Level[1].Limits, want)
	}
	if got.Level[2].Limits != nil {
		t.Errorf("level 2: limits %v without \"limits\"", got.Level[2].Limits)
	}
}
