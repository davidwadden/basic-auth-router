package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lager/lagerflags"
)

const (
	DefaultPort     = "8080"
	CFForwardedUrl  = "X-Cf-Forwarded-Url"
	DefaultUsername = "user"
	DefaultPassword = "password"
)

var c *config

type config struct {
	username string
	password string
	port     string
}

func main() {
	lagerflags.AddFlags(flag.CommandLine)

	flag.Parse()

	//logger := lager.NewLogger("p-basic-auth-router")
	logger, reconfigurableSink := lagerflags.New("p-basic-auth-router")
	logger.Info("starting")

	logger.RegisterSink(lager.NewWriterSink(os.Stdout, reconfigurableSink.GetMinLevel()))
	logger.RegisterSink(lager.NewWriterSink(os.Stderr, lager.ERROR))

	// Display the current minimum log level
	fmt.Printf("Current log level is ")
	switch reconfigurableSink.GetMinLevel() {
	case lager.DEBUG:
		fmt.Println("debug")
	case lager.INFO:
		fmt.Println("info")
	case lager.ERROR:
		fmt.Println("error")
	case lager.FATAL:
		fmt.Println("fatal")
	}

	c = configFromEnvironmentVariables()

	http.Handle("/", wrapper(newProxy()))
	logger.Fatal("http-listen", http.ListenAndServe(":"+getPort(), nil))
}

func configFromEnvironmentVariables() *config {
	conf := &config{
		username: getEnv("BASIC_AUTH_USERNAME", DefaultUsername),
		password: getEnv("BASIC_AUTH_PASSWORD", DefaultPassword),
		port:     getPort(),
	}

	return conf
}

func newProxy() http.Handler {
	logger, reconfigurableSink := lagerflags.New("p-basic-auth-router.new-proxy")
	logger.RegisterSink(lager.NewWriterSink(os.Stdout, reconfigurableSink.GetMinLevel()))

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			forwardedURL := req.Header.Get(CFForwardedUrl)
			url, err := url.Parse(forwardedURL)
			if err != nil {
				log.Fatalln(err.Error())
			}

			req.URL = url
			req.Host = url.Host

			logger.Debug("X-Cf-Forwarded-URL", lager.Data{
				"X-Cf-Forwarded-Url": req.Header.Get(CFForwardedUrl),
			})

			logger.Debug("X-CF-Proxy-Signature", lager.Data{
				"X-CF-Proxy-Signature": req.Header.Get("X-CF-Proxy-Signature"),
			})

			logger.Debug("X-CF-Proxy-Metadata", lager.Data{
				"X-CF-Proxy-Metadata": req.Header.Get("X-CF-Proxy-Metadata"),
			})

		},
	}
	return proxy
}

func getPort() string {
	var port string
	if port = os.Getenv("PORT"); len(port) == 0 {
		port = DefaultPort
	}
	return port
}

func getEnv(env string, defaultValue string) string {
	var (
		v string
	)
	if v = os.Getenv(env); len(v) == 0 {
		log.Printf("using default: %v=%v", env, defaultValue)
		return defaultValue
	}

	log.Printf("using environment: %v=%v", env, v)
	return v
}

func wrapper(h http.Handler) http.Handler {
	logger, reconfigurableSink := lagerflags.New("p-basic-auth-router.wrapper")
	logger.RegisterSink(lager.NewWriterSink(os.Stdout, reconfigurableSink.GetMinLevel()))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if (len(c.username) > 0) && (len(c.password) > 0) && !auth(r, c.username, c.password) {
			username, password, ok := r.BasicAuth()
			logger.Debug("UnauthorizedRequest", lager.Data{
				"username": username,
				"password": password,
				"ok":       ok,
			})

			w.Header().Set("WWW-Authenticate", `Basic realm="REALM"`)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		username, password, ok := r.BasicAuth()
		logger.Debug("AuthenticatedRequest", lager.Data{
			"username": username,
			"password": password,
			"ok":       ok,
		})
		h.ServeHTTP(w, r)
	})
}

func auth(r *http.Request, user, pass string) bool {
	if username, password, ok := r.BasicAuth(); ok {
		return username == user && password == pass
	}
	return false
}
