package i18n

// The API core: the error envelope, sign-in and sessions, the panel's address,
// health, capabilities, tunnels' side information and pairing notes, address
// pools, reconcile, monitoring, diagnostics and metrics -- and the account,
// configuration and seed texts behind them.
func init() {
	register(map[string]string{
		// internal/api/errors.go
		"The response could not be encoded.":                       "پاسخ کدگذاری نشد.",
		"The request body is not valid JSON for this endpoint: %s": "بدنهٔ درخواست برای این نقطه پایانی JSON معتبری نیست: %s",

		// internal/api/middleware.go
		"The request could not be completed.":                                                           "درخواست کامل نشد.",
		"This origin is not allowed to call the API. Add it to security.allowed_origins.":               "این مبدأ اجازهٔ فراخوانی API را ندارد. آن را به security.allowed_origins بیفزایید.",
		"The panel could not read its database.":                                                        "پنل نتوانست پایگاه داده‌اش را بخواند.",
		"No operator account exists yet. Create the first account before using the panel.":              "هنوز هیچ حساب اپراتوری وجود ندارد. پیش از استفاده از پنل، نخستین حساب را بسازید.",
		"Authentication is required.":                                                                   "احراز هویت لازم است.",
		"This session ended when the password was changed. Sign in again.":                              "این نشست با تغییر گذرواژه پایان یافت. دوباره وارد شوید.",
		"This account is not active.":                                                                   "این حساب فعال نیست.",
		"The session is not valid. Sign in again.":                                                      "نشست معتبر نیست. دوباره وارد شوید.",
		"The session could not be verified.":                                                            "بررسی نشست انجام نشد.",
		"This request is missing a valid CSRF token. Send the value of the %s cookie in the %s header.": "این درخواست توکن CSRF معتبری ندارد. مقدار کوکی %s را در سرایند %s بفرستید.",

		// internal/api/router.go, static.go, sse.go
		"No such endpoint.":                                    "چنین نقطه پایانی‌ای وجود ندارد.",
		"That method is not allowed on this endpoint.":         "این متد روی این نقطه پایانی مجاز نیست.",
		"Tunnel management is not available on this instance.": "مدیریت تونل در این نمونه از پنل در دسترس نیست.",
		"Interface listing is not available on this instance.": "فهرست رابط‌ها در این نمونه از پنل در دسترس نیست.",
		"Route listing is not available on this instance.":     "فهرست مسیرها در این نمونه از پنل در دسترس نیست.",
		"That method is not allowed here.":                     "این متد اینجا مجاز نیست.",
		"This connection cannot carry a live stream.":          "این اتصال نمی‌تواند جریان زنده را حمل کند.",

		// internal/api/domain_errors.go
		"This change cannot be made to the running interface. Confirm that it may be deleted and rebuilt, which briefly interrupts the tunnel.": "این تغییر روی رابطِ در حال کار انجام‌شدنی نیست. تأیید کنید که می‌توان آن را حذف کرد و از نو ساخت؛ این کار تونل را برای مدتی کوتاه قطع می‌کند.",
		"The operation could not be completed.": "عملیات کامل نشد.",
		"No netfilter backend is available on this host, so forwarding rules cannot be applied here. Install nftables or iptables.": "هیچ پیاده‌سازی netfilter روی این سرور در دسترس نیست، پس قانون‌های فوروارد اینجا اعمال نمی‌شوند. nftables یا iptables را نصب کنید.",

		// internal/api/auth.go
		"An operator account already exists. Sign in instead.": "یک حساب اپراتور از پیش وجود دارد. به‌جای آن وارد شوید.",
		"Too many failed sign-in attempts. Try again later.":   "تلاش‌های ناموفق ورود بیش از حد بود. بعداً دوباره تلاش کنید.",
		"Too many sign-in attempts. Try again in a minute.":    "تلاش‌های ورود بیش از حد بود. یک دقیقهٔ دیگر دوباره تلاش کنید.",
		"Invalid username or password.":                        "نام کاربری یا گذرواژه نادرست است.",
		"The sign-in could not be completed.":                  "ورود کامل نشد.",
		"account is locked until %s":                           "حساب تا %s قفل است",
		"No refresh token was supplied.":                       "هیچ توکن تمدید نشستی فرستاده نشد.",
		"The refresh token is not valid. Sign in again.":       "توکن تمدید نشست معتبر نیست. دوباره وارد شوید.",
		"The session could not be refreshed.":                  "نشست تمدید نشد.",
		"Supply a new username, a new password, or both.":      "نام کاربری تازه، گذرواژهٔ تازه یا هر دو را بدهید.",
		"The change could not be completed.":                   "تغییر کامل نشد.",
		"The current password is not correct.":                 "گذرواژهٔ کنونی درست نیست.",
		"The session could not be created.":                    "نشست ساخته نشد.",
		"Password must be at least %d characters.":             "گذرواژه باید دست‌کم %d نویسه باشد.",
		"Password must be at most %d characters.":              "گذرواژه باید حداکثر %d نویسه باشد.",
		"That username is already in use.":                     "این نام کاربری از پیش به کار رفته است.",

		// internal/auth
		"password is too easy to guess":                                                            "حدس زدن این گذرواژه بیش از حد آسان است",
		"password is too easy to guess: it is one character repeated":                              "حدس زدن این گذرواژه بیش از حد آسان است: یک نویسه است که تکرار شده",
		"password is too easy to guess: it is a straight run of consecutive characters":            "حدس زدن این گذرواژه بیش از حد آسان است: رشته‌ای از نویسه‌های پشت‌سرهم است",
		"password is too easy to guess: it is only whitespace":                                     "حدس زدن این گذرواژه بیش از حد آسان است: فقط فاصلهٔ خالی است",
		"invalid username or password":                                                             "نام کاربری یا گذرواژه نادرست است",
		"too many login attempts":                                                                  "تلاش‌های ورود بیش از حد بود",
		"account is not active":                                                                    "حساب فعال نیست",
		"username must be 1-64 characters from A-Z a-z 0-9 . _ - and start with a letter or digit": "نام کاربری باید ۱ تا ۶۴ نویسه از A-Z a-z 0-9 . _ - باشد و با یک حرف یا رقم آغاز شود",
		`verifying password for "%s": %w`:                                                          "بررسی گذرواژهٔ «%s»: %w",
		"locking account: %w":                                                                      "قفل کردن حساب: %w",
		"recording failed login: %w":                                                               "ثبت ورود ناموفق: %w",
		"recording successful login: %w":                                                           "ثبت ورود موفق: %w",
		"reading user: %w":                                                                         "خواندن کاربر: %w",

		// internal/api/audit.go
		"That is not a known audit action.": "این کار در تاریخچه شناخته‌شده نیست.",
		"The audit log could not be read.":  "تاریخچه خوانده نشد.",

		// internal/api/address.go
		"This panel was not started by systemd, so it cannot restart itself. A change made here is stored and takes effect the next time the panel starts.": "این پنل با systemd راه‌اندازی نشده است، پس نمی‌تواند خودش را دوباره راه‌اندازی کند. تغییری که اینجا بدهید ذخیره می‌شود و دفعهٔ بعد که پنل راه‌اندازی شود اثر می‌کند.",
		"Give a port, a web path, or both.":                                                                                               "یک پورت، یک مسیر وب یا هر دو را بدهید.",
		"The panel is already at that address, so there is nothing to change.":                                                            "پنل همین حالا روی این نشانی است، پس چیزی برای تغییر نیست.",
		"The panel is restarting and will answer at the new address.":                                                                     "پنل دارد دوباره راه‌اندازی می‌شود و روی نشانی تازه پاسخ می‌دهد.",
		"The new address was stored. This panel was not started by systemd, so it cannot restart itself; restart it to apply the change.": "نشانی تازه ذخیره شد. این پنل با systemd راه‌اندازی نشده است، پس نمی‌تواند خودش را دوباره راه‌اندازی کند؛ برای اعمال تغییر، آن را دوباره راه‌اندازی کنید.",
		"A port must be between 1 and 65535; %d is not.":                                                                                  "پورت باید بین ۱ و ۶۵۵۳۵ باشد؛ %d چنین نیست.",
		"Port %d cannot be used: %s.":                                                                                                     "پورت %d را نمی‌توان به کار برد: %s.",
		"Port %d cannot be bound on %s, so the panel would not come back on it: %s.":                                                      "پنل نمی‌تواند پورت %d را روی %s بگیرد، پس روی آن بالا نمی‌آمد: %s.",

		// internal/config
		`path traversal is not allowed in "%s"`:                     "پیمایش مسیر در «%s» مجاز نیست",
		"character %q is not allowed; use only A-Z a-z 0-9 . _ ~ -": "نویسهٔ %q مجاز نیست؛ فقط از A-Z a-z 0-9 . _ ~ - استفاده کنید",
		"web path is %d characters; the maximum is 128":             "مسیر وب %d نویسه است؛ بیشینه ۱۲۸ است",

		// internal/api/health.go
		"no database is configured": "هیچ پایگاه داده‌ای پیکربندی نشده است",
		"port %d could not be bound, so the panel is serving on %d instead: %s": "پورت %d گرفته نشد، پس پنل به‌جای آن روی %d پاسخ می‌دهد: %s",
		"netlink is not usable, so tunnels cannot be configured: %s":            "netlink قابل استفاده نیست، پس تونل‌ها پیکربندی نمی‌شوند: %s",
		"loaded": "بارگذاری‌شده",
		"not loaded; it autoloads when the first tunnel is created": "بارگذاری نشده؛ با ساخته‌شدن نخستین تونل خودکار بارگذاری می‌شود",
		"the monitor supervisor is not running":                     "ناظر پایش در حال اجرا نیست",
		"%d prober(s) running":                                      "%d پروب در حال اجرا",
		"the metrics sampler is not running":                        "نمونه‌بردار سنجه‌ها در حال اجرا نیست",
		"no reading has been taken yet":                             "هنوز هیچ خوانشی گرفته نشده است",
		"the last reading was %s ago":                               "آخرین خوانش %s پیش بود",
		"the last reading was %s ago, so sampling has stalled":      "آخرین خوانش %s پیش بود، پس نمونه‌برداری از کار مانده است",

		// internal/api/system.go
		"tunnel management is not available on this instance":                                 "مدیریت تونل در این نمونه از پنل در دسترس نیست",
		"systemd-networkd is running, so networkd persistence can be offered":                 "systemd-networkd در حال اجراست، پس ماندگاری با networkd را می‌توان پیشنهاد داد",
		"systemd-networkd is not active on this host, so networkd persistence is not offered": "systemd-networkd روی این سرور فعال نیست، پس ماندگاری با networkd پیشنهاد نمی‌شود",
		"Systemd":  "یونیت systemd",
		"Networkd": "فایل‌های systemd-networkd",
		"Runtime":  "فقط تا راه‌اندازی بعدی",
		"renders a systemd unit; the tunnel returns after a reboot":        "یک یونیت systemd می‌سازد؛ تونل پس از راه‌اندازی دوباره برمی‌گردد",
		"configures the running kernel only and does not survive a reboot": "فقط کرنلِ در حال اجرا را پیکربندی می‌کند و پس از راه‌اندازی دوباره باقی نمی‌ماند",
		"forwarding rules are not available on this instance":              "قانون‌های فوروارد در این نمونه از پنل در دسترس نیستند",

		// internal/api/tunnels.go
		"This code is configuration, not a credential. It carries the GRE key, which is not a security boundary, but it describes a specific pair of hosts and should not be posted publicly.": "این کد پیکربندی است، نه گواهی دسترسی. کلید GRE را با خود دارد که مرز امنیتی نیست، اما یک جفت سرور مشخص را توصیف می‌کند و نباید به‌طور عمومی منتشر شود.",
		"Nothing has been created. Review these values and submit them to create the tunnel on this server.":                                                                                   "هنوز چیزی ساخته نشده است. این مقادیر را بررسی کنید و بفرستید تا تونل روی این سرور ساخته شود.",
		"A and B are simply the two ends of one tunnel. The choice is arbitrary and neither end has a special role — GRE has no client, server, initiator, or responder. Use A on the first server you set up and B on the second. The only differences are that A takes the first address in the tunnel subnet and B takes the second, and that the local and remote endpoints are mirrored between them. Every other setting — key, MTU, TTL — must match exactly on both servers, or the tunnel will appear up while carrying no traffic.": "A و B فقط دو سرِ یک تونل‌اند. این انتخاب دلخواه است و هیچ‌کدام از دو سر نقش ویژه‌ای ندارد — GRE کلاینت، سرور، آغازگر یا پاسخ‌دهنده ندارد. روی نخستین سروری که راه می‌اندازید A و روی دومی B را به کار ببرید. تنها تفاوت‌ها این است که A نخستین نشانی زیرشبکهٔ تونل را می‌گیرد و B دومی را، و نقطه‌های پایانی محلی و دور میان آن دو قرینه‌اند. هر تنظیم دیگری — کلید، MTU، TTL — باید روی هر دو سرور دقیقاً یکسان باشد، وگرنه تونل برقرار به نظر می‌رسد در حالی که هیچ ترافیکی حمل نمی‌کند.",
		"this server is the local endpoint and the peer is the remote one": "این سرور نقطه پایانی محلی است و همتا نقطه پایانی دور",
		"the first usable address":    "نخستین نشانی قابل استفاده",
		"the label for slot a":        "برچسب جایگاه a",
		"mirrored relative to slot a": "قرینهٔ جایگاه a",
		"the second usable address":   "دومین نشانی قابل استفاده",
		"the label for slot b":        "برچسب جایگاه b",
		"tunnel type":                 "نوع تونل",
		"inbound key":                 "کلید ورودی",
		"outbound key":                "کلید خروجی",
		"checksum flags":              "پرچم‌های checksum",
		"sequence flags":              "پرچم‌های sequence",
		"The tunnel identifier in the path is not a number.": "شناسهٔ تونل در مسیر یک عدد نیست.",

		// internal/api/patch.go
		"must be a whole number or null": "باید یک عدد صحیح یا null باشد",
		"must be a number or null":       "باید یک عدد یا null باشد",

		// internal/api/pools.go
		"A pool needs a name.": "استخر به یک نام نیاز دارد.",
		"The range must be written in CIDR form, such as 172.17.0.0/16.": "محدوده باید به شکل CIDR نوشته شود، مانند 172.17.0.0/16.",
		"The pool identifier in the path is not a number.":               "شناسهٔ استخر در مسیر یک عدد نیست.",

		// internal/db: the seeded address pools
		"Private 172.17.0.0/16": "خصوصی 172.17.0.0/16",
		"Private 10.10.0.0/16":  "خصوصی 10.10.0.0/16",
		"Legacy 109.194.0.0/16": "قدیمی 109.194.0.0/16",
		"Legacy 87.107.0.0/16":  "قدیمی 87.107.0.0/16",
		"Default RFC 1918 range. Matches the range the legacy install script used by default.": "محدودهٔ پیش‌فرض RFC 1918. همان محدوده‌ای است که اسکریپت نصب قدیمی به‌طور پیش‌فرض به کار می‌برد.",
		"Alternative RFC 1918 range, for installations where 172.17.0.0/16 is already in use.": "محدودهٔ جایگزین RFC 1918، برای نصب‌هایی که 172.17.0.0/16 در آن‌ها از پیش به کار رفته است.",
		"Compatibility only. This is a globally routable block: assigning it to a tunnel squats on someone else's address space and blackholes those destinations from this server. Enable only to adopt tunnels that already use it.": "فقط برای سازگاری. این یک بلوک قابل مسیریابی در سطح جهانی است: تخصیص آن به یک تونل فضای نشانی کس دیگری را اشغال می‌کند و آن مقصدها را برای این سرور به سیاه‌چاله می‌فرستد. فقط برای پذیرش تونل‌هایی که از پیش از آن استفاده می‌کنند فعالش کنید.",

		// internal/api/reconcile.go
		"The record has been dropped. The interface %s was not touched and is still on this host.":                                           "رکورد حذف شد. به رابط %s دست زده نشد و هنوز روی این سرور است.",
		"Ignoring an interface only stops it being reported. The panel never changes or removes an interface it does not manage either way.": "نادیده گرفتن یک رابط فقط گزارش شدنش را متوقف می‌کند. پنل در هر حال رابطی را که مدیریت نمی‌کند هرگز تغییر نمی‌دهد یا حذف نمی‌کند.",

		// internal/api/monitor.go
		"Monitoring is not available on this instance.":  "پایش در این نمونه از پنل در دسترس نیست.",
		"monitoring has not reported on this tunnel yet": "پایش هنوز دربارهٔ این تونل گزارشی نداده است",
		"The from parameter is not a time: %s":           "پارامتر from یک زمان نیست: %s",
		"The to parameter is not a time: %s":             "پارامتر to یک زمان نیست: %s",

		// internal/api/diagnostics.go
		"Diagnostics are not available on this instance.": "عیب‌یابی در این نمونه از پنل در دسترس نیست.",
		"The run identifier in the path is not a number.": "شناسهٔ اجرا در مسیر یک عدد نیست.",

		// internal/api/metrics.go
		"System metrics are not available on this instance.": "سنجه‌های سامانه در این نمونه از پنل در دسترس نیستند.",
	})
}
