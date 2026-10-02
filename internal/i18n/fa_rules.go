package i18n

// Port forwarding: the netfilter backends, and traffic limits.
//
// A sentinel error's English begins with its package ("rules: "), because Go
// errors do; the Persian leaves it out, since it is not part of the sentence.
func init() {
	register(map[string]string{
		// internal/rules/rules.go: sentinels and the structural check
		"rules: no netfilter backend is available on this host":            "هیچ پیاده‌سازی netfilter روی این سرور در دسترس نیست",
		"rules: unsupported by this backend":                               "این پیاده‌سازی از آن پشتیبانی نمی‌کند",
		"rules: the rule has no enabled destination":                       "قانون هیچ مقصد فعالی ندارد",
		"rules: the bind and destination port ranges are different widths": "بازه‌های پورت شنود و مقصد هم‌اندازه نیستند",
		"rules: this file was not written by the panel":                    "این فایل را پنل ننوشته است",
		"rules: a rule needs an identifier to be rendered":                 "قانون برای ساخته شدن به یک شناسه نیاز دارد",
		"rules: %q is not a protocol":                                      "%q یک پروتکل نیست",
		"rules: %q is not a NAT mode":                                      "%q یک حالت NAT نیست",
		"rules: %q is not a load balancing mode":                           "%q یک حالت توزیع بار نیست",
		"rules: the rule has no enabled destination: rule %d":              "قانون %d هیچ مقصد فعالی ندارد",
		"rules: rule %d uses SNAT but names no source address":             "قانون %d از SNAT استفاده می‌کند اما هیچ نشانی مبدأ نمی‌دهد",
		"rules: the bind and destination port ranges are different widths: rule %d binds %s (%d ports) and sends to %s (%d ports)": "بازه‌های پورت شنود و مقصد هم‌اندازه نیستند: قانون %d روی %s (%d پورت) گوش می‌دهد و به %s (%d پورت) می‌فرستد",

		// internal/rules/detect.go
		"development mode: rules are rendered but never applied to this host":                                                           "حالت توسعه: قانون‌ها ساخته می‌شوند اما هرگز روی این سرور اعمال نمی‌شوند",
		"iptables was selected explicitly, so the panel keeps to the interface the rest of this host is managed with":                   "iptables صراحتاً انتخاب شده است، پس پنل به همان ابزاری پایبند می‌ماند که بقیهٔ این سرور با آن مدیریت می‌شود",
		"nft is available, so the panel owns one nftables table and replaces it atomically without touching anything else on this host": "nft در دسترس است، پس پنل یک جدول nftables از آنِ خود دارد و آن را یکجا و اتمی جایگزین می‌کند، بی‌آنکه به چیز دیگری روی این سرور دست بزند",
		"nft was not found, so the panel falls back to iptables with its own chains":                                                    "nft پیدا نشد، پس پنل به iptables با زنجیره‌های خودش روی می‌آورد",
		"neither nft nor iptables was found on this host, so forwarding rules cannot be applied here":                                   "نه nft و نه iptables روی این سرور پیدا نشد، پس قانون‌های فوروارد اینجا اعمال نمی‌شوند",

		// internal/rules/fake.go, foreign.go
		"in-memory backend used for preview and tests; it renders exactly what %s would apply and then changes nothing on this host": "پیاده‌سازی درون‌حافظه‌ای برای پیش‌نمایش و آزمون؛ دقیقاً همان چیزی را می‌سازد که %s اعمال می‌کرد و سپس هیچ چیزی را روی این سرور تغییر نمی‌دهد",
		"%s in %s, which belongs to %s": "%s در %s، که از آنِ %s است",
		"%s in %s":                      "%s در %s",

		// internal/rules/iptables.go
		"the iptables and iptables-restore binaries were not both found on this system": "دست‌کم یکی از فایل‌های اجرایی iptables و iptables-restore روی این سیستم پیدا نشد",
		"iptables with dedicated panel-owned chains, restored with --noflush so only the panel's own chains are rebuilt; these binaries speak to the legacy netfilter backend, which does not share tables with nftables rules on this host": "iptables با زنجیره‌های اختصاصی پنل، که با --noflush بازگردانده می‌شوند تا فقط زنجیره‌های خودِ پنل از نو ساخته شوند؛ این فایل‌های اجرایی با پیاده‌سازی قدیمی (legacy) netfilter کار می‌کنند که روی این سرور جدول‌هایش را با قانون‌های nftables شریک نمی‌شود",
		"iptables with dedicated panel-owned chains, restored with --noflush so only the panel's own chains are rebuilt":                                                                                                                     "iptables با زنجیره‌های اختصاصی پنل، که با --noflush بازگردانده می‌شوند تا فقط زنجیره‌های خودِ پنل از نو ساخته شوند",
		"rules: no netfilter backend is available on this host: iptables and iptables-restore were not both found":                                                                                                                           "هیچ پیاده‌سازی netfilter روی این سرور در دسترس نیست: دست‌کم یکی از iptables و iptables-restore پیدا نشد",
		"%s jump from the %s table's %s chain into %s":                                      "پرش %[1]s از زنجیرهٔ %[3]s جدول %[2]s به %[4]s",
		"rules: unsupported by this backend: load balancing across a port range (%s on %s)": "این پیاده‌سازی پشتیبانی نمی‌کند: توزیع بار روی یک بازهٔ پورت (%s روی %s)",
		"rules: unsupported by this backend: source-hash load balancing on the iptables backend needs the destinations to be a contiguous address range sharing one port; use round robin, or run the nftables backend, which hashes across any set of destinations": "این پیاده‌سازی پشتیبانی نمی‌کند: توزیع بار بر پایهٔ هش مبدأ در پیاده‌سازی iptables نیاز دارد که مقصدها یک بازهٔ پیوستهٔ نشانی با یک پورت مشترک باشند؛ از round robin استفاده کنید، یا پیاده‌سازی nftables را به کار ببرید که روی هر مجموعه‌ای از مقصدها هش می‌کند",
		"rules: unsupported by this backend: load balancing mode %q": "این پیاده‌سازی پشتیبانی نمی‌کند: حالت توزیع بار %q",
		"restoring the panel's %s rules: %w":                         "بازگرداندن قانون‌های %s پنل: %w",
		"installing the %s: %w":                                      "نصب %s: %w",
		"reading the panel's counters: %w":                           "خواندن شمارنده‌های پنل: %w",
		"the host's nat table could not be listed: %s":               "جدول nat این سرور فهرست نشد: %s",
		"listing the host nat table: %w":                             "فهرست کردن جدول nat سرور: %w",
		"removing the jump from %s/%s: %w":                           "حذف پرش از %s/%s: %w",
		"removing the chain %s: %w":                                  "حذف زنجیرهٔ %s: %w",

		// internal/rules/nftables.go
		"native nftables in a table owned entirely by the panel; changes are one atomic transaction and coexist with other tables on this host": "nftables بومی در جدولی که سراسر از آنِ پنل است؛ هر تغییر یک تراکنش اتمی است و در کنار جدول‌های دیگر این سرور کار می‌کند",
		"the nft binary was not found on this system":                                         "فایل اجرایی nft روی این سیستم پیدا نشد",
		"rules: no netfilter backend is available on this host: the nft binary was not found": "هیچ پیاده‌سازی netfilter روی این سرور در دسترس نیست: فایل اجرایی nft پیدا نشد",
		"applying the nftables ruleset: %w":                                                   "اعمال مجموعه قانون‌های nftables: %w",
		"reading the panel's nftables table: %w":                                              "خواندن جدول nftables پنل: %w",
		"reading the counter list: %w":                                                        "خواندن فهرست شمارنده‌ها: %w",
		"the host's nftables ruleset could not be listed: %s":                                 "مجموعه قانون‌های nftables این سرور فهرست نشد: %s",
		"listing the host ruleset: %w":                                                        "فهرست کردن مجموعه قانون‌های سرور: %w",
		"removing the panel's nftables table: %w":                                             "حذف جدول nftables پنل: %w",

		// internal/rules/socket.go
		"%s (pid %d) is listening on %s/%s":                                                      "%s (pid %d) روی %s/%s گوش می‌دهد",
		"%s is listening on %s/%s":                                                               "%s روی %s/%s گوش می‌دهد",
		"a process this panel cannot identify is listening on %s/%s":                             "فرایندی که این پنل نمی‌شناسد روی %s/%s گوش می‌دهد",
		"%s (pid %d) is listening on %s/every local address on port %d":                          "%[1]s (pid %[2]d) روی پورت %[4]d (%[3]s) در همهٔ نشانی‌های محلی گوش می‌دهد",
		"%s is listening on %s/every local address on port %d":                                   "%[1]s روی پورت %[3]d (%[2]s) در همهٔ نشانی‌های محلی گوش می‌دهد",
		"a process this panel cannot identify is listening on %s/every local address on port %d": "فرایندی که این پنل نمی‌شناسد روی پورت %[2]d (%[1]s) در همهٔ نشانی‌های محلی گوش می‌دهد",

		// internal/rules/store.go
		"rules: this file was not written by the panel: %s": "این فایل را پنل ننوشته است: %s",
		"creating %s: %w":   "ساختن %s: %w",
		"installing %s: %w": "نصب %s: %w",

		// internal/quota/quota.go
		"no traffic limit is set here":                   "اینجا سقف ترافیکی تنظیم نشده است",
		"starting it again: %w":                          "راه‌اندازی دوبارهٔ آن: %w",
		"unknown scope %d":                               "دامنهٔ ناشناختهٔ %d",
		"reading a traffic limit: %w":                    "خواندن یک سقف ترافیک: %w",
		"storing a traffic limit: %w":                    "ذخیرهٔ یک سقف ترافیک: %w",
		"updating a traffic limit: %w":                   "به‌روزرسانی یک سقف ترافیک: %w",
		"removing a traffic limit: %w":                   "حذف یک سقف ترافیک: %w",
		"the destination %s no longer exists on rule %d": "مقصد %s دیگر روی قانون %d وجود ندارد",
		"scope has to be tunnel, rule or destination":    "دامنه باید tunnel، rule یا destination باشد",

		// internal/api/quota.go
		"Traffic limits are not available on this instance.":                              "سقف ترافیک روی این نمونه در دسترس نیست.",
		"A tunnel limit needs the tunnel's id.":                                           "سقف ترافیک تونل به شناسهٔ تونل نیاز دارد.",
		"A rule limit needs the rule's id.":                                               "سقف ترافیک قانون به شناسهٔ قانون نیاز دارد.",
		"A destination limit needs the rule's id and the destination's address and port.": "سقف ترافیک مقصد به شناسهٔ قانون و نشانی و پورت مقصد نیاز دارد.",
	})
}
