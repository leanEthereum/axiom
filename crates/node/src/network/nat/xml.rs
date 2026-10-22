//! A minimal reader for the few XML elements UPnP exchanges need.
//!
//! It finds elements by local name, ignoring namespace prefixes and attributes.
//! It does not validate the document, and an element must not nest inside one of its own name.
//! UPnP device descriptions and SOAP replies meet that: no element read here nests in itself.

/// A slice of XML text: a whole document or one element's content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Xml<'a>(pub(crate) &'a str);

impl<'a> Xml<'a> {
    /// The content of every element with a local name, in document order.
    pub(crate) fn elements(self, name: &str) -> Vec<Self> {
        let mut found = Vec::new();
        let mut rest = self.0;
        while let Some((content, after)) = Self::next_element(rest, name) {
            found.push(Self(content));
            rest = after;
        }
        found
    }

    /// The content of the first element with a local name.
    pub(crate) fn first(self, name: &str) -> Option<Self> {
        Self::next_element(self.0, name).map(|(content, _)| Self(content))
    }

    /// The text of the first element with a local name, trimmed and unescaped.
    pub(crate) fn text_of(self, name: &str) -> Option<String> {
        self.first(name).map(Self::text)
    }

    /// The content as text: surrounding whitespace trimmed, the five predefined entities unescaped.
    pub(crate) fn text(self) -> String {
        // Each entity is replaced once, ampersand last, so an escaped entity stays literal.
        self.0
            .trim()
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&")
    }

    /// The content of the next element with a local name, and the text after its end tag.
    fn next_element(text: &'a str, name: &str) -> Option<(&'a str, &'a str)> {
        let mut from = 0;
        loop {
            // Phase 1: the next start tag, skipping end tags, comments, and declarations.
            let open = from + text.get(from..)?.find('<')?;
            let close = open + text.get(open..)?.find('>')?;
            let tag = &text[open + 1..close];
            from = close + 1;
            if tag.starts_with(['/', '!', '?']) {
                continue;
            }
            // The qualified name runs to the first space, slash, or end of tag.
            let qualified = tag
                .split(|c: char| c.is_ascii_whitespace() || c == '/')
                .next()
                .unwrap_or_default();
            let local = qualified.rsplit(':').next().unwrap_or_default();
            if local != name {
                continue;
            }
            // Phase 2: a self-closing element is empty.
            if tag.ends_with('/') {
                return Some(("", &text[from..]));
            }
            // Phase 3: the end tag repeats the qualified name.
            let end = format!("</{qualified}>");
            let length = text.get(from..)?.find(&end)?;
            return Some((
                &text[from..from + length],
                &text[from + length + end.len()..],
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elements_are_found_by_local_name() {
        // Prefixes, attributes, comments, and declarations do not get in the way.
        let document = r#"<?xml version="1.0"?>
            <!-- a gateway -->
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
              <s:Body><u:Reply xmlns:u="urn:x"><Value> 1 &amp; 2 </Value><Empty/></u:Reply></s:Body>
            </s:Envelope>"#;
        let xml = Xml(document);
        assert_eq!(xml.text_of("Value"), Some("1 & 2".to_owned()));
        assert_eq!(xml.text_of("Empty"), Some(String::new()));
        assert_eq!(
            xml.first("Reply").map(|reply| reply.text_of("Value")),
            Some(Some("1 & 2".to_owned()))
        );
        assert_eq!(xml.text_of("Missing"), None);
    }

    #[test]
    fn siblings_come_in_document_order() {
        let xml = Xml("<list><item>a</item><item>b</item><other>c</other><item>d</item></list>");
        let items: Vec<String> = xml.elements("item").into_iter().map(Xml::text).collect();
        assert_eq!(items, ["a", "b", "d"]);
    }

    #[test]
    fn entities_unescape_once() {
        // An escaped entity stays an entity: &amp;lt; reads as &lt;, not as <.
        assert_eq!(
            Xml("&lt;a&gt; &quot;b&quot; &apos;c&apos; &amp;lt;").text(),
            "<a> \"b\" 'c' &lt;"
        );
    }

    #[test]
    fn unterminated_elements_are_absent() {
        assert_eq!(Xml("<a>never closed").first("a"), None);
        assert_eq!(Xml("<a").first("a"), None);
    }
}
