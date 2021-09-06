package jwtware_test

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"

	jwtware "github.com/gofiber/jwt/v3"
)

type TestToken struct {
	SigningMethod string
	Token         string
}

var (
	hamac = []TestToken{
		{
			SigningMethod: jwtware.HS256,
			Token:         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o",
		},
		{
			SigningMethod: jwtware.HS384,
			Token:         "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.hO2sthNQUSfvI9ylUdMKDxcrm8jB3KL6Rtkd3FOskL-jVqYh2CK1es8FKCQO8_tW",
		},
		{
			SigningMethod: jwtware.HS512,
			Token:         "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.wUVS6tazE2N98_J4SH_djkEe1igXPu0qILAvVXCiO6O20gdf5vZ2sYFWX3c-Hy6L4TD47b3DSAAO9XjSqpJfag",
		},
	}

	rsa = []TestToken{
		{
			SigningMethod: jwtware.RS256,
			Token:         "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImdvZmliZXItcnNhIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.gvWLzl1sYUXdYqAPqFYLEJYtqPce8YxrV6LPiyWX2147llj1YfquFySnC8KOUTykCAxZHe6tFkyyZOp35HOqV3P-jxW2rw05mpNhld79f-O2sAFEzV7qxJXuYi4TL-Qn1gaLWP7i9B6B9c-0xLzYUmtLdrmlM2pxfPkXwG0oSao",
		},
		{
			SigningMethod: jwtware.RS384,
			Token:         "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImdvZmliZXItcnNhIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.IIFu5jNRT5fIe91we3ARLTpE8hGu4tK6gsWtrJ1lAWzCxUYsVE02yOi3ya9RJsh-37GN8LdfVw74ZQzr4dwuq8SorycVatA2bc_OfkWpioOoPCqGMBFgsEdue0qtL1taflA-YSNG-Qntpqx_ciCGfI1DhiqikLaL-LSe8H9YOWk",
		},
		{
			SigningMethod: jwtware.RS512,
			Token:         "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6ImdvZmliZXItcnNhIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.DKY-VXa6JJUZpupEUcmXETwaV2jfLydyeBfhSP8pIEW9g52fQ3g5hrHCNstxG2yy9yU68yrFqrBDetDX_yJ6qSHAOInwGWYot8W4D0lJvqsHJe0W0IPi03xiaWjwKO26xENCUzNNLvSPKPox5DPcg31gzCFBrIUgVX-TkpajuSE",
		},
	}

	// Create the test cases.
	testCases = []TestToken{
		{
			SigningMethod: jwtware.ES256,
			Token:         "eyJhbGciOiJFUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJDR3QwWldTNExjNWZhaUtTZGkwdFUwZmpDQWR2R1JPUVJHVTlpUjd0VjBBIn0.eyJleHAiOjE2MTU0MDY4NjEsImlhdCI6MTYxNTQwNjgwMSwianRpIjoiYWVmOWQ5YjItN2EyYy00ZmQ4LTk4MzktODRiMzQ0Y2VmYzZhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.iQ77QGoPDNjR2oWLu3zT851mswP8J-h_nrGhs3fpa_tFB3FT1deKPGkjef9JOTYFI-CIVxdCFtW3KODOaw9Nrw",
		},
		{
			SigningMethod: jwtware.ES384,
			Token:         "eyJhbGciOiJFUzM4NCIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUVkFBZXQ2M08zeHlfS0s2X2J4Vkl1N1JhM196MXdsQjU0M0Zid2k1VmFVIn0.eyJleHAiOjE2MTU0MDY4OTAsImlhdCI6MTYxNTQwNjgzMCwianRpIjoiYWNhNDU4NTItZTE0ZS00MjgxLTljZTQtN2ZiNzVkMTg1MWJmIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.oHFT-RvbNNT6p4_tIoZzr4IS88bZqy20cJhF6FZCIXALZ2dppoOjutanPVxzuLC5axG3P71noVghNUF8X44bTShP1boLrlde2QKmj5GxDR-oNEb9ES_zC10rZ5I76CwR",
		},
		{
			SigningMethod: jwtware.ES512,
			Token:         "eyJhbGciOiJFUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJlYkp4bm05QjNRREJsakI1WEpXRXU3MnF4NkJhd0RhTUFod3o0YUtQa1EwIn0.eyJleHAiOjE2MTU0MDY5MDksImlhdCI6MTYxNTQwNjg0OSwianRpIjoiMjBhMGI1MTMtN2E4My00OGQ2LThmNDgtZmQ3NDc1N2Y4OWRiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.AdR59BCvGlctL5BMgXlpJBBToKTPG4SVa-oJKBqE7qxvTSBwAQM5D3uUc2toM3NAUERSMKOLTJfzfxenNRixrDMnAcrdFHgEY10vsDp6uqA7NMUevHE5f7jiAVK1talXS9O41IEnR2DKbAG0GgjIA2WHLhUgftG2uNN8LMKI2QSbLCfM",
		},
		{
			SigningMethod: "ECDSA precomputed",
			Token:         "eyJhbGciOiJFUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJlYkp4bm05QjNRREJsakI1WEpXRXU3MnF4NkJhd0RhTUFod3o0YUtQa1EwIn0.eyJleHAiOjE2MTU0MDY5MDksImlhdCI6MTYxNTQwNjg0OSwianRpIjoiMjBhMGI1MTMtN2E4My00OGQ2LThmNDgtZmQ3NDc1N2Y4OWRiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.AdR59BCvGlctL5BMgXlpJBBToKTPG4SVa-oJKBqE7qxvTSBwAQM5D3uUc2toM3NAUERSMKOLTJfzfxenNRixrDMnAcrdFHgEY10vsDp6uqA7NMUevHE5f7jiAVK1talXS9O41IEnR2DKbAG0GgjIA2WHLhUgftG2uNN8LMKI2QSbLCfM",
		},
		{
			SigningMethod: jwtware.PS256,
			Token:         "eyJhbGciOiJQUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ6WGV3MFVKMWg2UTRDQ2NkXzl3eE16dmNwNWNFQmlmSDBLV3JDejJLeXhjIn0.eyJleHAiOjE2MTU0MDY5NjIsImlhdCI6MTYxNTQwNjkwMiwianRpIjoiNWIyZGY5N2EtNDQyOS00ZTA0LWFkMzgtOWZmNjVlZDU2MTZjIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.tafkUwLXm3lyyqJHwAGwFPN3IO0rCrESJnVcIuI1KHPSKogn5DgWqR3B9QCvqIusqlxhGW7MvOhG-9dIy62ciKGQFDRFA9T46TMm9t8O80TnhYTB8ImX90xYuf6E74k1RiqRVcubFWKHWlhKjqXMM4dD2l8VwqL45E6kHpNDvzvILKAfrMgm0vHsfi6v5rf32HLp6Ox1PvpKrM1kDgsdXm6scgAGJCTbOQB2Pzc-i8cyFPeuckbeL4zbM3-Odqc-eI-3pXevMzUB608J3fRpQK1W053kU7iG9RFC-5nBwvrBlN4Lff_X1R3JBLkFcA0wJeFYtIFnMm6lVbA7nwa0Xg"}, // Signing algorithm PS256.
		{
			SigningMethod: jwtware.PS384,
			Token:         "eyJhbGciOiJQUzM4NCIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJMeDFGbWF5UDJZQnR4YXFTMVNLSlJKR2lYUktudzJvdjVXbVlJTUctQkxFIn0.eyJleHAiOjE2MTU0MDY5ODIsImlhdCI6MTYxNTQwNjkyMiwianRpIjoiMGY2NGJjYTktYjU4OC00MWFhLWFkNDEtMmFmZDM2OGRmNTFkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.Rxrq41AxbWKIQHWv-Tkb7rqwel3sKT_R_AGvn9mPIHqhw1m7nsQWcL9t2a_8MI2hCwgWtYdgTF1xxBNmb2IW3CZkML5nGfcRrFvNaBHd3UQEqbFKZgnIX29h5VoxekyiwFaGD-0RXL83jF7k39hytEzTatwoVjZ-frga0KFl-nLce3OwncRXVCGmxoFzUsyu9TQFS2Mm_p0AMX1y1MAX1JmLC3WFhH3BohhRqpzBtjSfs_f46nE1-HKjqZ1ERrAc2fmiVJjmG7sT702JRuuzrgUpHlMy2juBG4DkVcMlj4neJUmCD1vZyZBRggfaIxNkwUhHtmS2Cp9tOcwNu47tSg"}, // Signing algorithm PS384.
		{
			SigningMethod: jwtware.PS512,
			Token:         "eyJhbGciOiJQUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ0VzZhZTdUb21FNl8yam9vTS1zZjlOXzZsV2c3SE50YVFYckRzRWxCek00In0.eyJleHAiOjE2MTU0MDcwMDUsImlhdCI6MTYxNTQwNjk0NSwianRpIjoiYzJmMmZiMjQtOTQ1Yi00YTA4LWE3ZTQtYTZhNzRlZTIwMDFiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.d5E6m_isNWy0Y5E-udUruMbThe3NHMb7x90rzOxlrEyyhZEqjuREP97KQXIospLY41TKj3VURJbRFebg-my4R8w1-OlaciDdoWND2juk8y_vIMlgYb9lLMnS1ZI5Ayq3OQ4Bh2TXLsZwQaBWoccyVSD1qCgZsCH-ZIbxJmefkM6k99fA8QWwNFL-bD1kHELBdZfk-26JSRWiA_0WocQZcC5DWsmbslwICo2yT59X4ancvxNA-mns0Wt41-sj9sAAr-qOAubGjpPC8-FqVZXeDTiuaAqQA2K3MRKMwHMZY6e-duwCltGll_kZf2jUlwfF7LLuT7YP6p7rxCjIhHaAMw"}, // Signing algorithm PS512.
	}
)

const (
	defaultSigningKey = "secret"
	defaultKeySet     = `
{
   "keys":[
   {
	  "e": "AQAB",
	  "kid": "gofiber-rsa",
	  "kty": "RSA",
	  "n": "2IPZysef6KVySrb_RPopuwWy1C7KRfE96zQ9jIRwPghlvs0yfj9VK4rqeYbuHp5k9ghbjm1Bn2LMLR-JzqYWbchxzVrV58ay4nRHYUSjyzdbNcG0J4W-NxHnVqK0UUOl59uikRDqGHh3eRen_jVO_B8lvhqM57HQhA-czHbsmeU"
	}
]
}
`
)

func TestJwtFromHeader(t *testing.T) {
	t.Parallel()

	defer func() {
		// Assert
		if err := recover(); err != nil {
			t.Fatalf("Middleware should not panic")
		}
	}()

	for _, test := range hamac {
		// Arrange
		app := fiber.New()

		app.Use(jwtware.New(jwtware.Config{
			SigningKey:    []byte(defaultSigningKey),
			SigningMethod: test.SigningMethod,
		}))

		app.Get("/ok", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/ok", nil)
		req.Header.Add("Authorization", "Bearer "+test.Token)

		// Act
		resp, err := app.Test(req)

		// Assert
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, 200, resp.StatusCode)
	}
}

func TestJwtFromCookie(t *testing.T) {
	t.Parallel()

	defer func() {
		// Assert
		if err := recover(); err != nil {
			t.Fatalf("Middleware should not panic")
		}
	}()

	for _, test := range hamac {
		// Arrange
		app := fiber.New()

		app.Use(jwtware.New(jwtware.Config{
			SigningKey:    []byte(defaultSigningKey),
			SigningMethod: test.SigningMethod,
			TokenLookup:   "cookie:Token",
		}))

		app.Get("/ok", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/ok", nil)
		cookie := &http.Cookie{
			Name:  "Token",
			Value: test.Token,
		}
		req.AddCookie(cookie)

		// Act
		resp, err := app.Test(req)

		// Assert
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, 200, resp.StatusCode)
	}
}

// TestJWKs performs a table test on the JWKs code.
func TestJwkFromServer(t *testing.T) {
	// Could add a test with an invalid JWKs endpoint.
	// Create a temporary directory to serve the JWKs from.
	tempDir, err := ioutil.TempDir("", "*")
	if err != nil {
		t.Errorf("Failed to create a temporary directory.\nError:%s\n", err.Error())
		t.FailNow()
	}
	defer func() {
		if err = os.RemoveAll(tempDir); err != nil {
			t.Errorf("Failed to remove temporary directory.\nError:%s\n", err.Error())
			t.FailNow()
		}
	}()

	// Create the JWKs file path.
	jwksFile := filepath.Join(tempDir, "jwks.json")

	// Write the empty JWKs.
	if err = ioutil.WriteFile(jwksFile, []byte(defaultKeySet), 0600); err != nil {
		t.Errorf("Failed to write JWKs file to temporary directory.\nError:%s\n", err.Error())
		t.FailNow()
	}

	// Create the HTTP test server.
	server := httptest.NewServer(http.FileServer(http.FS(os.DirFS(tempDir))))
	defer server.Close()

	// Iterate through the test cases.
	for _, test := range rsa {
		// Arrange
		app := fiber.New()

		app.Use(jwtware.New(jwtware.Config{
			KeySetURL: server.URL + "/jwks.json",
		}))

		app.Get("/ok", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/ok", nil)
		req.Header.Add("Authorization", "Bearer "+test.Token)

		// Act
		resp, err := app.Test(req)

		// Assert
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, 200, resp.StatusCode)
	}
}
