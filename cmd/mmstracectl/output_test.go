// SPDX-License-Identifier: MIT

package main

import (
	"testing"

	mms "github.com/otfabric/go-mms"

	"github.com/otfabric/go-mms-trace/trace"
)

func mmsName(scope mms.ObjectScope, domain, item string) mms.ObjectName {
	return mms.ObjectName{Scope: scope, Domain: mms.DomainID(domain), ItemID: mms.ItemID(item)}
}

func TestObject(t *testing.T) {
	hz := mmsName(mms.ObjectScopeDomain, "LD0", "MMXU1$MX$Hz")
	list := mmsName(mms.ObjectScopeDomain, "LD0", "LLN0$ds")
	cases := []struct {
		p    *mms.CapturedPDU
		want string
	}{
		{&mms.CapturedPDU{Variables: []mms.CapturedVariable{{Name: hz}, {Name: hz}, {Name: hz}}}, "LD0/MMXU1$MX$Hz (+2)"},
		{&mms.CapturedPDU{ListName: &list}, "list LD0/LLN0$ds"},
		{&mms.CapturedPDU{VariableName: &hz}, "LD0/MMXU1$MX$Hz"},
		{&mms.CapturedPDU{NameListRequest: &mms.CapturedNameListRequest{ObjectClass: 9, Scope: mms.ObjectScopeVMD}}, "class 9 (VMD)"},
		{&mms.CapturedPDU{}, ""},
	}
	for _, tc := range cases {
		if got := object(&trace.Transaction{Request: tc.p}); got != tc.want {
			t.Errorf("object = %q, want %q", got, tc.want)
		}
	}
	// A reject and an error in the JSON form.
	x := toTransaction(&trace.Transaction{Response: &mms.CapturedPDU{Reject: &mms.CapturedReject{Type: 1, Reason: 2},
		Error: &mms.CapturedServiceError{Class: 3, Code: 4}}})
	if x.Reject == nil || x.Reject.Reason != 2 || x.Error == nil || x.Error.Code != 4 || x.LatencyMS != nil {
		t.Errorf("transaction = %+v", x)
	}
	r := toReport(&trace.Report{PDU: &mms.CapturedPDU{ListName: &list, Values: []*mms.Value{mms.NewInteger(1)}}})
	if r.ListName != "LD0/LLN0$ds" || r.Values != 1 || reportName(r) != "LD0/LLN0$ds" {
		t.Errorf("report = %+v", r)
	}
	if g := toGoose(&trace.GooseStream{}); g.Issues == nil {
		t.Error("GOOSE issues nil")
	}
	in := toInfo(analysis{res: &trace.Result{File: trace.File{Gzip: true}}})
	if in.Links == nil || in.Unsupported == nil {
		t.Errorf("info = %+v", in)
	}
}
