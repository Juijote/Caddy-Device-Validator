// Package devicevalidator provides automatic mobile UA detection and header injection for Caddy
package devicevalidator

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

var _ caddyhttp.MiddlewareHandler = (*DeviceDetector)(nil)

// DeviceDetector 中间件，只检测移动 UA 并注入标头
type DeviceDetector struct{}

func init() {
	caddy.RegisterModule(DeviceDetector{})
	httpcaddyfile.RegisterHandlerDirective("vd_header", parseCaddyfile)
}

func (DeviceDetector) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.device_detector",
		New: func() caddy.Module { return new(DeviceDetector) },
	}
}

// ServeHTTP 注入移动 UA 检测标头
func (dd *DeviceDetector) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ua := r.Header.Get("User-Agent")
	isMobile := strings.Contains(ua, "Mobile")

	if isMobile {
		r.Header.Set("X-DV-UA", ua)
		r.Header.Set("X-DV-Device-Type", "mobile")

		tp := r.Header.Get("X-DV-Touch-Points")
		if tp == "" {
			tp = "-1"
		}
		r.Header.Set("X-DV-Touch-Points", tp)

		touchPoints, _ := strconv.Atoi(tp)
		if touchPoints <= 1 {
			r.Header.Set("X-DV-Suspicious-UA", "true")
		} else {
			r.Header.Set("X-DV-Suspicious-UA", "false")
		}

		// 只对 HTML 页面注入 JS
		if strings.HasSuffix(r.URL.Path, ".html") || strings.HasSuffix(r.URL.Path, "/") {
			// 使用自定义 ResponseWriter 捕获输出
			crw := &captureResponseWriter{ResponseWriter: w, buf: new(bytes.Buffer)}
			err := next.ServeHTTP(crw, r)
			if err != nil {
				return err
			}
			// 在 HTML 尾部注入 JS
			modified := injectTouchPointsJS(crw.buf.Bytes())
			w.Header().Set("Content-Length", strconv.Itoa(len(modified)))
			_, _ = w.Write(modified)
			return nil
		}
	}

	return next.ServeHTTP(w, r)
}

// captureResponseWriter 用于捕获下游输出
type captureResponseWriter struct {
	http.ResponseWriter
	buf *bytes.Buffer
}

func (c *captureResponseWriter) Write(p []byte) (int, error) {
	return c.buf.Write(p)
}

// injectTouchPointsJS 在 HTML 尾部注入 JS
func injectTouchPointsJS(content []byte) []byte {
	script := `
<script>
(function(){
  const tp = navigator.maxTouchPoints || 0;

  const origFetch = window.fetch;
  window.fetch = function(input, init){
    init = init || {};
    init.headers = init.headers || {};
    init.headers['X-DV-Touch-Points'] = tp.toString();
    return origFetch(input, init);
  };

  const origXhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(){
    this.addEventListener('readystatechange', function(){
      this.setRequestHeader('X-DV-Touch-Points', tp.toString());
    }, false);
    origXhrOpen.apply(this, arguments);
  };

  document.addEventListener('submit', function(e){
    const form = e.target;
    if(form.method.toLowerCase() === 'post'){
      let input = document.createElement('input');
      input.type = 'hidden';
      input.name = 'X-DV-Touch-Points';
      input.value = tp.toString();
      form.appendChild(input);
    }
  }, true);
})();
</script>
</body>`

	// 尝试在 </body> 前插入 JS
	if idx := bytes.LastIndex(content, []byte("</body>")); idx != -1 {
		modified := make([]byte, 0, len(content)+len(script))
		modified = append(modified, content[:idx]...)
		modified = append(modified, []byte(script)...)
		modified = append(modified, content[idx+7:]...) // 7 = len("</body>")
		return modified
	}
	// 如果没有 </body>，直接追加
	return append(content, []byte(script)...)
}

// Caddyfile helper（无需参数即可启用）
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	return &DeviceDetector{}, nil
}
