package core

import (
	"context"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

// Config holds all the application configuration and state.
type Config struct {
	UrlFlag             string
	ListFlag            string
	WaybackFlag         bool
	GauFlag             bool
	VerboseFlag         bool
	ResponseFlag        bool
	DetailedFlag        string
	JsonFlag            string
	HelpFlag            bool
	Thread              int
	ProxyFlag           string
	ScanDepthFlag       int
	HtmlReportFlag      string
	ExcludeFlag         string
	TimeoutFlag         int
	RetryFlag           int
	SaveFlag            string
	SaveGfFlag          string
	SaveUroFlag         string
	KatanaFlag          bool
	UrlfindFlag         bool
	ArjunFlag           bool
	GospiderFlag        bool
	HakrawlerFlag       bool
	AllFlag             bool

	// Internal state
	ProcessedDomains    int64
	UrlCache            *cache.Cache
	Log                 *logrus.Logger
	Ctx                 context.Context
	Cancel              context.CancelFunc
	UserAgents          []string
	ExcludedPatterns    []string
}

// Configuration constants
const (
	DefaultTimeout        = 30
	DefaultRetryAttempts  = 3
	DefaultRetryDelay     = 5 * time.Second
	DefaultScanDepth      = 2
	DefaultBatchSize      = 50
	DefaultCacheExpiry    = 5 * time.Minute
	DefaultCacheCleanup   = 10 * time.Minute
	DefaultRateLimitDelay = 5 * time.Second
)
