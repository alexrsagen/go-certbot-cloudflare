package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

var errInconsistent = errors.New("[error] Inconsistent record count from CF_NS1 and CF_NS2")

func lookupCompareTXT(rs1 net.Resolver, rs2 net.Resolver, name string) ([]string, error) {
	wg := &sync.WaitGroup{}

	var res1, res2 []string
	var err1, err2 error

	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)

	wg.Add(2)
	go func() {
		res1, err1 = rs1.LookupTXT(ctx, name)
		wg.Done()
	}()
	go func() {
		res2, err2 = rs2.LookupTXT(ctx, name)
		wg.Done()
	}()
	wg.Wait()
	cancel()

	if err1 != nil {
		return nil, err1
	} else if err2 != nil {
		return nil, err2
	}
	if res1 == nil {
		return nil, errors.New("[error] Nameserver from CF_NS1 did not respond")
	} else if res2 == nil {
		return nil, errors.New("[error] Nameserver from CF_NS2 did not respond")
	}

	if len(res1) != len(res2) {
		return nil, errInconsistent
	}

	for i := range res1 {
		found := false
		for j := range res2 {
			if res2[j] == res1[i] {
				found = true
				break
			}
		}
		if !found {
			return nil, errInconsistent
		}
	}

	return res1, nil
}

func strSliceLookup(haystack []string, needle string) bool {
	for i := range haystack {
		if haystack[i] == needle {
			return true
		}
	}
	return false
}
