// Copyright © 2019 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"net/http/httputil"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var localAddress string
var writeDistributorAddress string
var readDistributorAddress string
var jwtSecret string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cortex-proxy",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {

		router := mux.NewRouter()

		router.HandleFunc("/api/prom/push", performRedirectWithInject)
		router.PathPrefix("/api/").HandlerFunc(frontEndProxy)

		srv := &http.Server{
			Handler: router,
			Addr:    localAddress,
			// Good practice: enforce timeouts for servers you create!
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		}

		log.Fatal(srv.ListenAndServe())
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cortex-proxy.yaml)")
	rootCmd.Flags().StringVarP(&localAddress, "lAddress", "l", "localhost:8080", "local server:port")
	rootCmd.Flags().StringVarP(&writeDistributorAddress, "wAddress", "w", "http://localhost:9009/api/prom/push", "Remote address to proxy http://cortex-server:port/api/prom/push")
	rootCmd.Flags().StringVarP(&readDistributorAddress, "rAddress", "r", "http://localhost:9009/api/prom", "Remote cortex read address http://cortex-server:port/api/prom")
	rootCmd.Flags().StringVarP(&jwtSecret, "jwtsecret", "j", "", "JWT secret for the token")
	rootCmd.MarkFlagRequired("jwtsecret")
	rootCmd.MarkFlagRequired("lAddress")
	rootCmd.MarkFlagRequired("wAddress")
	rootCmd.MarkFlagRequired("rAddress")
	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".cortex-proxy" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".cortex-proxy")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func performRedirectWithInject(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	token = strings.Split(token, "Bearer ")[1]
	tenantID := parseToken(token)
	log.Printf("performRedirectWithInject:Tenant id is %s", tenantID)
	url, _ := url.Parse(writeDistributorAddress)
	r.Header.Set("X-Scope-OrgID", tenantID)
	proxy := &httputil.ReverseProxy{Director: director(url)}
	proxy.ServeHTTP(w, r)

}

func frontEndProxy(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	tenantID := parseToken(token)
	log.Printf("frontEndProxy:Tenant id is %s", tenantID)
	url, _ := url.Parse(readDistributorAddress)
	r.Header.Set("X-Scope-OrgID", tenantID)
	proxy := &httputil.ReverseProxy{Director: director(url)}
	proxy.ServeHTTP(w, r)

}

func director(targetURL *url.URL) func(req *http.Request) {
	targetQuery := targetURL.RawQuery

	return func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", targetURL.Host)
		req.Header.Add("X-Origin-Host", targetURL.Host)

		req.URL.Scheme = "http"
		req.URL.Host = targetURL.Host
		//req.URL.Path = targetURL.Path
		req.URL.Path = singleJoiningSlash(targetURL.Path, req.URL.Path)

		log.Println("director: Req URL Scheme ", req.URL.Scheme)
		log.Println("director: Req URL Host ", req.URL.Host)
		log.Println("director: Req URL Path", req.URL.Path)

		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
		log.Println("director: Req URL Query ", req.URL.RawQuery)
	}
}

func parseToken(tokenString string) string {
	var tenantID string

	hmacSampleSecret := []byte(jwtSecret)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return hmacSampleSecret, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		tenantID = fmt.Sprint(claims["tenant_id"])
	} else {
		log.Println(err)
	}
	return tenantID
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
