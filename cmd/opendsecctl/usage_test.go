package main

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
)

func TestPrintUsage(t *testing.T) {
	rep := &pb.UsageReport{AsOf: 1792800000, Rows: []*pb.UsageRow{
		{Project: "root/a", Day: "2026-10-22", SandboxesStarted: 2, SandboxHours: 1, CpuCoreHours: 2, MemoryGbHours: 4},
		{Project: "root/a", Day: "2026-10-23", SandboxHours: 0.5, CpuCoreHours: 1, MemoryGbHours: 2},
		{Project: "root/b", Day: "2026-10-23", SandboxesStarted: 1, SandboxHours: 3, CpuCoreHours: 3, MemoryGbHours: 3, GpuHours: 3},
	}}
	var b bytes.Buffer
	printUsage(&b, rep, false, true)
	want := "PROJECT,SANDBOXES,SANDBOX_H,CPU_CORE_H,MEM_GB_H,GPU_H\nroot/a,2,1.50,3.00,6.00,0.00\nroot/b,1,3.00,3.00,3.00,3.00\nTOTAL,3,4.50,6.00,9.00,3.00\n"
	if b.String() != want {
		t.Fatalf("per project:\n%s", b.String())
	}
	b.Reset()
	printUsage(&b, rep, true, true)
	if lines := strings.Split(strings.TrimSpace(b.String()), "\n"); len(lines) != 5 || lines[1] != "2026-10-22,root/a,2,1.00,2.00,4.00,0.00" {
		t.Fatalf("daily:\n%s", b.String())
	}
	b.Reset()
	printUsage(&b, rep, false, false)
	if !strings.Contains(b.String(), "TOTAL") || !strings.Contains(b.String(), "as of 2026-") {
		t.Fatalf("table:\n%s", b.String())
	}
}
