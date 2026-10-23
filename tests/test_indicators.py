from phish_triage.indicators import analyse, score
from phish_triage.parse import parse_email


def names(raw):
    return {i.name for i in analyse(parse_email(raw))}


def test_paypal_spoof_indicators(sample):
    n = names(sample("paypal_spoof.eml"))
    for expected in ["display_name_spoof", "reply_to_mismatch", "spf_fail", "dmarc_fail",
                     "ip_url", "link_text_mismatch", "urgency_language", "credential_request", "risky_tld"]:
        assert expected in n, expected


def test_invoice_indicators(sample):
    n = names(sample("invoice_attachment.eml"))
    assert {"risky_attachment", "url_shortener", "urgency_language", "spf_fail"} <= n


def test_benign_samples_are_clean(sample):
    for f in ["newsletter_benign.eml", "colleague_benign.eml"]:
        inds = analyse(parse_email(sample(f)))
        assert score(inds)[1] == "likely_benign", (f, inds)


def test_punycode_and_brand_domain():
    raw = (b"From: Bank <a@example.com>\nSubject: hi\nContent-Type: text/html\n\n"
           b'<a href="https://xn--pypal-4ve.com/login">login</a> <a href="https://apple-id-check.example.net">x</a>')
    n = names(raw)
    assert "punycode_domain" in n and "brand_in_foreign_domain" in n


def test_score_thresholds():
    from phish_triage.indicators import Indicator
    assert score([])[1] == "likely_benign"
    assert score([Indicator("a", 3, "")])[1] == "suspicious"
    assert score([Indicator("a", 3, ""), Indicator("b", 2.5, "")])[1] == "phishing"


def test_injection_sample_still_phishing(sample):
    inds = analyse(parse_email(sample("injection_in_body.eml")))
    assert score(inds)[1] == "phishing"
