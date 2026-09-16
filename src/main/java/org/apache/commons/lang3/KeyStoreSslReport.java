package org.apache.commons.lang3;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.auth.x500.X500Principal;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.lang3.function.FailableFunction;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.validator.routines.DomainValidator;
import org.d2ab.function.ObjIntPredicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import io.github.toolfactory.narcissus.Narcissus;

public class KeyStoreSslReport {

	private static final String VALUE = "value";

	private static final String INITIALIZED = "initialized";

	private static final String DELEGATE = "delegate";

	private static final Logger LOG = LoggerFactory.getLogger(KeyStoreSslReport.class);

	public static void main(final String[] args) throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException, ParserConfigurationException, SAXException, XPathExpressionException {
		//
		final Map<String, String> map = toMap(args);
		//
		if (containsKey(map, "config")) {
			//
			final DocumentBuilder db = newDocumentBuilder(DocumentBuilderFactory.newDefaultInstance());
			//
			File file = new File(get(map, "config"));
			//
			final Document document = db != null && file.exists() && file.isFile() ? db.parse(file) : null;
			//
			final XPathFactory xpf = XPathFactory.newDefaultInstance();
			//
			final XPath xp = xpf != null ? xpf.newXPath() : null;
			//
			final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			//
			info(LOG, "File      ={}", getAbsolutePath(file = testAndApply(Objects::nonNull,
					Objects.toString(evaluate(xp, "/*/keyStore", document)), File::new, null)));
			//
			info(LOG, "");
			//
			try (final InputStream is = testAndApply(x -> x != null && x.exists(), file, FileInputStream::new, null)) {
				//
				load(keyStore, is, toCharArray(get(map, Objects.toString(evaluate(xp, "/*/password", document)))));
				//
				final NodeList nodeList = cast(NodeList.class,
						evaluate(xp, "/*/urls/url", document, XPathConstants.NODESET));
				//
				Node node = null;
				//
				for (int i = 0; nodeList != null && i < nodeList.getLength(); i++) {
					//
					if ((node = nodeList.item(i)) == null) {
						//
						continue;
						//
					} // if
						//
					perform(keyStore, node.getTextContent());
					//
					info(LOG, "");
					//
				} // for
					//
			} // try
				//
		} else {
			//
			final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			//
			final File file = testAndApply(Objects::nonNull, get(map, "keyStore"), File::new, null);
			//
			info(LOG, "File      ={}", getAbsolutePath(file));
			//
			try (final InputStream is = testAndApply(Objects::nonNull, file, FileInputStream::new, null)) {
				//
				load(keyStore, is, toCharArray(get(map, "password")));
				//
				perform(keyStore, get(map, "url"));
				//
			} // try
				//
		} // if
			//
	}

	private static DocumentBuilder newDocumentBuilder(final DocumentBuilderFactory instance)
			throws ParserConfigurationException {
		return instance != null ? instance.newDocumentBuilder() : null;
	}

	private static Object evaluate(final XPath instance, final String string, final Object object, final QName qName)
			throws XPathExpressionException {
		return instance != null && object != null ? instance.evaluate(string, object, qName) : null;
	}

	private static Object evaluate(final XPath instance, final String string, final Object object)
			throws XPathExpressionException {
		return instance != null && object != null ? instance.evaluate(string, object) : null;
	}

	private static boolean containsKey(final Map<?, ?> instance, final Object key) {
		return instance != null && instance.containsKey(key);
	}

	private static void perform(final KeyStore keyStore, final String url) throws KeyStoreException, IOException {
		//
		String alias, lcs = null;
		//
		Certificate certificate = null;
		//
		X509Certificate x509Certificate = null;
		//
		Date notAfter = null;
		//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(url), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (url == null || (field != null && Narcissus.getField(url, field) != null)) {
			//
			info(LOG, "URL       ={}", url);
			//
		} // if
			//
		Map<String, X509Certificate> map = null;
		//
		final Enumeration<String> aliases = aliases(keyStore);
		//
		while (hasMoreElements(aliases)) {
			//
			if ((isCertificateEntry(keyStore, alias = nextElement(aliases)) || isKeyEntry(keyStore, alias))
					&& (certificate = getCertificate(keyStore, alias)) instanceof X509Certificate
					&& (x509Certificate = (X509Certificate) certificate) != null
					&& isValid(DomainValidator.getInstance(),
							lcs = longestCommonSubstring(getName(getSubjectX500Principal(x509Certificate)), url))
					&& ((notAfter = getNotAfter(get(map = ObjectUtils.getIfNull(map, LinkedHashMap::new), lcs))) == null
							|| ObjectUtils.compare(getNotAfter(x509Certificate), notAfter) > 0)) {
				//
				put(map, lcs, x509Certificate);
				//
			} // if
				//
		} // while
			//
		final String longest = orElse(max(stream(keySet(map)), Comparator.comparingInt(StringUtils::length)), "");
		//
		info(LOG, url, collect(filter(stream(entrySet(map)), x -> Objects.equals(getKey(x), longest)),
				Collectors.toMap(x -> getKey(x), x -> getValue(x))));
		//
	}

	private static void info(final Logger logger, final String url, final Map<String, X509Certificate> map)
			throws IOException {
		//
		if (entrySet(map) == null) {
			//
			return;
			//
		} // if
			//
		X509Certificate x509Certificate = null;
		//
		DateFormat df = null;
		//
		Entry<String, Date> temp = null;
		//
		Long difference = null;
		//
		for (final Entry<String, X509Certificate> entry : entrySet(map)) {
			//
			if ((x509Certificate = getValue(entry)) == null) {
				//
				continue;
				//
			} // if
				//
			info(logger, "KeyStore  ={} {} ", getKey(entry),
					format(df = ObjectUtils.getIfNull(df, () -> new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")),
							getNotAfter(x509Certificate)));
			//
			info(logger, "HTTPS     ={} {}", getKey(temp = getEntry(url)), format(df, getValue(temp)));
			//
			if ((difference = substract(getValue(temp), getNotAfter(x509Certificate))) != null
					&& difference.longValue() != 0) {
				//
				info(logger, "Difference={}",
						DurationFormatUtils.formatDurationWords(difference.longValue(), false, false));
				//
			} // if
				//
		} // for
			//
	}

	private static String getAbsolutePath(final File instance) {
		return instance != null && instance.getPath() != null ? instance.getAbsolutePath() : null;
	}

	private static Long substract(final Date a, final Date b) {
		return a != null && b != null ? Long.valueOf(a.getTime() - b.getTime()) : null;
	}

	private static void info(final Logger instance, final String format, final Object... arguments) {
		if (instance != null) {
			instance.info(format, arguments);
		}
	}

	private static X500Principal getSubjectX500Principal(final X509Certificate instance) {
		return instance != null ? instance.getSubjectX500Principal() : null;
	}

	private static Entry<String, Date> getEntry(final String url) throws IOException {
		//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(url), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		final HttpsURLConnection httpsURLConnection = cast(HttpsURLConnection.class,
				openConnection(testAndApply(x -> x != null && (field == null || Narcissus.getField(x, field) != null),
						url, URL::new, null)));
		//
		connect(httpsURLConnection);
		//
		final Certificate[] certificates = getServerCertificates(httpsURLConnection);
		//
		final DomainValidator domainValidator = DomainValidator.getInstance();
		//
		final List<Certificate> list = collect(
				filter(testAndApply(Objects::nonNull, certificates, Arrays::stream, null),
						x -> isValid(domainValidator,
								longestCommonSubstring(url,
										getName(getSubjectX500Principal(cast(X509Certificate.class, x)))))),
				Collectors.toList());
		//
		X509Certificate x509Certificate = null;
		//
		String name = null;
		//
		Date date = null;
		//
		for (int i = 0; i < size(list); i++) {
			//
			if (date != null) {
				//
				throw new IllegalStateException();
				//
			} // if
				//
			name = StringUtils.substringAfter(
					getName(getSubjectX500Principal(x509Certificate = cast(X509Certificate.class, get(list, i)))), '=');
			//
			date = getNotAfter(x509Certificate);
			//
		} // for
			//
		disconnect(httpsURLConnection);
		//
		return Pair.of(name, date);
		//
	}

	private static Date getNotAfter(final X509Certificate instance) {
		return instance != null ? instance.getNotAfter() : null;
	}

	private static void disconnect(final HttpsURLConnection instance) {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), DELEGATE)), Collectors.toList()),
				x -> get(x, 0), null);

		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.disconnect();
			//
		} // if
			//
	}

	private static void connect(final HttpsURLConnection instance) throws IOException {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), DELEGATE)), Collectors.toList()),
				x -> get(x, 0), null);

		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.connect();
			//
		} // if
			//
	}

	private static Certificate[] getServerCertificates(final HttpsURLConnection instance)
			throws SSLPeerUnverifiedException {
		//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), DELEGATE)), Collectors.toList()),
				x -> get(x, 0), null);

		//
		return instance != null && (field == null || Narcissus.getField(instance, field) != null)
				? instance.getServerCertificates()
				: null;
		//
	}

	private static <T> T cast(final Class<T> clz, final Object instance) {
		return clz != null && clz.isInstance(instance) ? clz.cast(instance) : null;
	}

	private static URLConnection openConnection(final URL instance) throws IOException {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "handler")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.openConnection() : null;
		//
	}

	private static Certificate getCertificate(final KeyStore instance, final String alias) throws KeyStoreException {
		//
		if (instance == null || alias == null) {
			//
			return null;
			//
		} // if
			//
		Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), INITIALIZED)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null
				|| (Objects.equals(field.getType(), Boolean.TYPE)) && !Narcissus.getBooleanField(instance, field)) {
			//
			return null;
			//
		} // if
			//
		if ((field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(alias), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null)) != null && Narcissus.getField(alias, field) == null) {
			//
			return null;
			//
		} // if
			//
		return instance.getCertificate(alias);
		//
	}

	private static boolean isKeyEntry(final KeyStore instance, final String alias) throws KeyStoreException {
		//
		if (instance == null || alias == null) {
			//
			return false;
			//
		} // if
			//
		Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), INITIALIZED)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null
				|| (Objects.equals(field.getType(), Boolean.TYPE)) && !Narcissus.getBooleanField(instance, field)) {
			//
			return false;
			//
		} // if
			//
		if ((field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(alias), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null)) != null && Narcissus.getField(alias, field) == null) {
			//
			return false;
			//
		} // if
			//
		return instance.isKeyEntry(alias);
		//
	}

	private static boolean isCertificateEntry(final KeyStore instance, final String alias) throws KeyStoreException {
		//
		if (instance == null || alias == null) {
			//
			return false;
			//
		} // if
			//
		Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), INITIALIZED)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null
				|| (Objects.equals(field.getType(), Boolean.TYPE)) && !Narcissus.getBooleanField(instance, field)) {
			//
			return false;
			//
		} // if
			//
		if ((field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(alias), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null)) != null && Narcissus.getField(alias, field) == null) {
			//
			return false;
			//
		} // if
			//
		return instance.isCertificateEntry(alias);
		//
	}

	private static boolean hasMoreElements(final Enumeration<?> instance) {
		return instance != null && instance.hasMoreElements();
	}

	private static <E> E nextElement(final Enumeration<E> instance) {
		return instance != null ? instance.nextElement() : null;
	}

	private static Enumeration<String> aliases(final KeyStore instance) throws KeyStoreException {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), INITIALIZED)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null
				|| (Objects.equals(field.getType(), Boolean.TYPE)) && !Narcissus.getBooleanField(instance, field)) {
			//
			return null;
			//
		} // if
			//
		return instance.aliases();
		//
	}

	private static boolean isValid(final DomainValidator instance, final String domain) {
		//
		if (instance == null) {
			//
			return false;
			//
		} // if
			//
		Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "domainRegex")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field != null && Narcissus.getField(instance, field) == null) {
			//
			return false;
			//
		} // if
			//
		if ((field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(domain), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null)) != null && Narcissus.getField(domain, field) == null) {
			//
			return false;
			//
		} // if
			//
		return domain != null && instance.isValid(domain);
		//
	}

	private static void load(final KeyStore instance, final InputStream stream, final char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "keyStoreSpi")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.load(stream, password);
			//
		} // if
			//
	}

	private static <T> T orElse(final Optional<T> instance, final T other) {
		return instance != null ? instance.orElse(other) : other;
	}

	private static <T> Optional<T> max(final Stream<T> instance, final Comparator<? super T> comparator) {
		return instance != null ? instance.max(comparator) : null;
	}

	private static <K, V> Collection<Entry<K, V>> entrySet(final Map<K, V> instance) {
		return instance != null ? instance.entrySet() : null;
	}

	private static <K> Set<K> keySet(final Map<K, ?> instance) {
		return instance != null ? instance.keySet() : null;
	}

	private static String format(final DateFormat instance, final Date date) {
		//
		if (instance == null || date == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "calendar")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.format(date) : null;
		//
	}

	private static char[] toCharArray(final String instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.toCharArray() : null;
		//
	}

	private static <V> V get(final Map<?, V> instance, final Object key) {
		return instance != null ? instance.get(key) : null;
	}

	private static Map<String, String> toMap(final String... ss) {
		//
		String s = null;
		//
		Map<String, String> map = null;
		//
		Field field = null;
		//
		for (int i = 0; i < length(ss); i++) {
			//
			s = ArrayUtils.get(ss, i);
			//
			if (field == null) {
				//
				field = testAndApply(x -> size(x) == 1,
						collect(filter(
								stream(testAndApply(Objects::nonNull, getClass(s), FieldUtils::getAllFieldsList, null)),
								f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
						x -> get(x, 0), null);
				//
			} // if
				//
			if (s != null && field != null && Narcissus.getField(s, field) == null) {
				//
				continue;
				//
			} // if
				//
			if (Objects.equals(s = ArrayUtils.get(ss, i), "=")) {
				//
				put(map = ObjectUtils.getIfNull(map, LinkedHashMap::new), "", "");
				//
			} else if (s != null && s.length() == 2 && s.charAt(0) == '=') {
				//
				put(map = ObjectUtils.getIfNull(map, LinkedHashMap::new), "", s.substring(1, s.length()));
				//
			} else if (s != null && s.length() == 2 && s.charAt(s.length() - 1) == '=') {
				//
				put(map = ObjectUtils.getIfNull(map, LinkedHashMap::new), s.substring(0, s.length() - 1), "");
				//
			} else if (s != null && s.indexOf('=') >= 0 && s.indexOf('=') == s.lastIndexOf('=')) {
				//
				put(map = ObjectUtils.getIfNull(map, LinkedHashMap::new), StringUtils.substringBefore(s, '='),
						StringUtils.substringAfter(s, '='));
				//
			} else if (s != null && s.length() > 2 && s.indexOf('=') != s.lastIndexOf('=')) {
				//
				put(map = ObjectUtils.getIfNull(map, LinkedHashMap::new), StringUtils.substring(s, 0, s.indexOf('=')),
						StringUtils.substring(s, s.indexOf('=') + 1));
				//
			} // if
				//
		} // for
			//
		return map;
		//
	}

	private static int length(final Object[] instance) {
		return instance != null ? instance.length : 0;
	}

	private static <K> K getKey(final Entry<K, ?> instance) {
		return instance != null ? instance.getKey() : null;
	}

	private static <V> V getValue(final Entry<?, V> instance) {
		return instance != null ? instance.getValue() : null;
	}

	private static <K, V> void put(final Map<K, V> instance, final K key, final V value) {
		if (instance != null) {
			instance.put(key, value);
		}
	}

	private static String longestCommonSubstring(final String a, final String b) {
		//
		int start = 0, max = 0;
		//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(stream(testAndApply(Objects::nonNull, getClass(a), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		final boolean conditionA = or(field, Objects::isNull, f -> Narcissus.getField(a, f) != null);
		//
		final boolean conditionB = or(field, Objects::isNull,
				f -> and(b, Objects::nonNull, g -> Narcissus.getField(g, f) != null));
		//
		for (int i = 0; and(conditionA, (value, index) -> index < StringUtils.length(value), a, i); i++) {
			//
			for (int j = 0; and(conditionB, (value, index) -> index < StringUtils.length(value), b, j); j++) {
				//
				int x = 0;
				//
				while (a.charAt(i + x) == b.charAt(j + x)) {
					//
					x++;
					//
					if (((i + x) >= a.length()) || ((j + x) >= b.length())) {
						//
						break;
						//
					} // if
						//
				} // while
					//
				if (x > max) {
					//
					max = x;
					//
					start = i;
					//
				} // if
					//
			} // for
				//
		} // for
			//
		return conditionA ? StringUtils.substring(a, start, start + max) : null;
		//
	}

	private static <T> boolean and(final boolean condition, final ObjIntPredicate<T> objIntPredicate, final T value,
			final int integer) {
		return condition && objIntPredicate != null && objIntPredicate.test(value, integer);
	}

	private static <T> boolean and(final T value, final Predicate<T> a, final Predicate<T> b) {
		return test(a, value) && test(b, value);
	}

	private static <T> boolean or(final T value, final Predicate<T> a, final Predicate<T> b) {
		return test(a, value) || test(b, value);
	}

	private static int size(final Collection<?> instance) {
		return instance != null ? instance.size() : 0;
	}

	private static <E> E get(final List<E> instance, final int index) {
		return instance != null ? instance.get(index) : null;
	}

	private static String getName(final X500Principal instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "thisX500Name")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.getName() : null;
		//
	}

	private static String getName(final Member instance) {
		return instance != null ? instance.getName() : null;
	}

	private static <T, R, A> R collect(final Stream<T> instance, final Collector<? super T, A, R> collector) {
		//
		return instance != null && (collector != null || Proxy.isProxyClass(getClass(instance)))
				? instance.collect(collector)
				: null;
		//
	}

	private static <T> Stream<T> filter(final Stream<T> instance, final Predicate<? super T> predicate) {
		return instance != null ? instance.filter(predicate) : instance;
	}

	private static <T> Stream<T> stream(final Collection<T> instance) {
		return instance != null ? instance.stream() : null;
	}

	private static Class<?> getClass(final Object instance) {
		return instance != null ? instance.getClass() : null;
	}

	private static <T, R, E extends Throwable> R testAndApply(final Predicate<T> predicate, final T value,
			final FailableFunction<T, R, E> functionTrue, final FailableFunction<T, R, E> functionFalse) throws E {
		return test(predicate, value) ? apply(functionTrue, value) : apply(functionFalse, value);
	}

	private static <T> boolean test(final Predicate<T> instance, final T value) {
		return instance != null && instance.test(value);
	}

	private static <T, R, E extends Throwable> R apply(final FailableFunction<T, R, E> instance, final T value)
			throws E {
		return instance != null ? instance.apply(value) : null;
	}

}