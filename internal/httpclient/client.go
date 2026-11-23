package httpclient

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"time"
)

type Client struct {
	hc        *http.Client
	userAgent string
}

func New(timeout time.Duration, userAgent string) *Client {
	return &Client{
		hc: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     30 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		userAgent: userAgent,
	}
}

type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Latency    time.Duration
}

func (c *Client) Do(ctx context.Context, method, url string, body io.Reader) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "*/*")
	start := time.Now()
	resp, err := c.hc.Do(req)
	lat := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
	return &Response{StatusCode: resp.StatusCode, Headers: resp.Header, Body: data, Latency: lat}, nil
}