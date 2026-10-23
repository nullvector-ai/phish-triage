from phish_triage.parse import parse_email


def test_parse_html_links(sample):
    m = parse_email(sample("paypal_spoof.eml"))
    assert m.from_addr == "service@paypa1-support.xyz"
    assert m.from_domain == "paypa1-support.xyz"
    assert m.reply_to == "helpdesk@protonmail-secure.top"
    assert m.links[0].href.startswith("http://192.168.13.37")
    assert m.links[0].text == "https://www.paypal.com/signin"
    assert "unusual sign-in activity" in m.text


def test_parse_attachment_and_plain_links(sample):
    m = parse_email(sample("invoice_attachment.eml"))
    assert m.attachments == ["Invoice_4471.pdf.exe"]
    assert any("bit.ly" in l.href for l in m.links)


def test_parse_str_input():
    m = parse_email("From: a@b.com\nSubject: hi\n\nhello")
    assert m.subject == "hi" and m.text == "hello"
