//  Copyright 2019 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

// Package config stores and retrieves configuration settings for the OS Config agent.
package config

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestSetConfig(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"project":{"projectId":"projectId","attributes":{"os-config-endpoint":"bad!!1","os-inventory-enabled":"false","os-patch-enabled":"true","os-package-enabled":"true"}},"instance":{"id":12345,"name":"name","zone":"zone","attributes":{"os-config-endpoint":"SvcEndpoint","os-inventory-enabled":"1","os-patch-enabled":"false","os-package-enabled":"foo", "os-debug-enabled":"true", "os-config-poll-interval":"3"}}}`)
	}))
	defer ts.Close()

	if err := os.Setenv("GCE_METADATA_HOST", strings.Trim(ts.URL, "http://")); err != nil {
		t.Fatalf("Error running os.Setenv: %v", err)
	}

	if err := SetConfig(); err != nil {
		t.Fatalf("Error running SetConfig: %v", err)
	}

	testsString := []struct {
		desc string
		op   func() string
		want string
	}{
		{"SvcEndpoint", SvcEndpoint, "SvcEndpoint"},
		{"Instance", Instance, "zone/instances/name"},
		{"ID", ID, "12345"},
		{"ProjectID", ProjectID, "projectId"},
		{"Zone", Zone, "zone"},
		{"Name", Name, "name"},
	}
	for _, tt := range testsString {
		if tt.op() != tt.want {
			t.Errorf("%q: got(%q) != want(%q)", tt.desc, tt.op(), tt.want)
		}
	}

	testsBool := []struct {
		desc string
		op   func() bool
		want bool
	}{
		{"osinventory should be enabled (proj disabled, inst enabled)", OSInventoryEnabled, true},
		{"ospatch should be disabled (proj enabled, inst disabled)", OSPatchEnabled, false},
		{"ospackage should be disabled (proj enabled, inst bad value)", OSPackageEnabled, false},
		{"debugenabled should be true (proj disabled, inst enabled)", Debug, true},
	}
	for _, tt := range testsBool {
		if tt.op() != tt.want {
			t.Errorf("%q: got(%t) != want(%t)", tt.desc, tt.op(), tt.want)
		}
	}

	if SvcPollInterval().Minutes() != float64(3) {
		t.Errorf("Default poll interval: got(%f) != want(%d)", SvcPollInterval().Minutes(), 3)
	}
}

func TestSetConfigDefaultValues(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"instance":{"id":12345,"name":"name","zone":"zone"}}`)
	}))
	defer ts.Close()

	if err := os.Setenv("GCE_METADATA_HOST", strings.Trim(ts.URL, "http://")); err != nil {
		t.Fatalf("Error running os.Setenv: %v", err)
	}

	if err := SetConfig(); err != nil {
		t.Fatalf("Error running SetConfig: %v", err)
	}

	testsString := []struct {
		desc string
		op   func() string
		want string
	}{
		{"Instance", Instance, "zone/instances/name"},
		{"ID", ID, "12345"},
		{"ProjectID", ProjectID, "projectId"},
		{"Zone", Zone, "zone"},
		{"Name", Name, "name"},
	}
	for _, tt := range testsString {
		if tt.op() != tt.want {
			t.Errorf("%q: got(%q) != want(%q)", tt.desc, tt.op(), tt.want)
		}
	}

	testsBool := []struct {
		desc string
		op   func() bool
		want bool
	}{
		{"osinventory should be enabled (proj disabled, inst enabled)", OSInventoryEnabled, osInventoryEnabledDefault},
		{"ospatch should be disabled (proj enabled, inst disabled)", OSPatchEnabled, osPatchEnabledDefault},
		{"ospackage should be disabled (proj enabled, inst bad value)", OSPackageEnabled, osPackageEnabledDefault},
		{"debugenabled should be true (proj disabled, inst enabled)", Debug, osDebugEnabledDefault},
	}
	for _, tt := range testsBool {
		if tt.op() != tt.want {
			t.Errorf("%q: got(%t) != want(%t)", tt.desc, tt.op(), tt.want)
		}
	}

	if SvcPollInterval().Minutes() != float64(osConfigPollIntervalDefault) {
		t.Errorf("Default poll interval: got(%f) != want(%d)", SvcPollInterval().Minutes(), osConfigPollIntervalDefault)
	}

	if SvcEndpoint() != prodEndpoint {
		t.Errorf("Default endpoint: got(%s) != want(%s)", SvcEndpoint(), prodEndpoint)
	}
}
