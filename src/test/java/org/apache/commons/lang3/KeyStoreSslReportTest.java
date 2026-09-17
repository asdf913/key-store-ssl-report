package org.apache.commons.lang3;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.CodeSource;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.ProtectionDomain;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;

import javax.net.ssl.HttpsURLConnection;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.lang3.function.FailableFunction;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.commons.validator.routines.DomainValidator;
import org.d2ab.function.ObjIntPredicate;
import org.slf4j.Logger;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.google.common.base.Predicates;
import com.google.common.reflect.Reflection;

import io.github.toolfactory.narcissus.Narcissus;

public class KeyStoreSslReportTest {

	private static Method METHOD_GET_NAME, METHOD_GET_CERTIFICATE, METHOD_LOAD, METHOD_IS_KEY_ENTRY,
			METHOD_IS_CERTIFICATE_ENTRY, METHOD_IS_VALID, METHOD_FORMAT, METHOD_TO_CHAR_ARRAY,
			METHOD_LONGEST_COMMON_SUB_STRING, METHOD_SUBSTRACT, METHOD_GET_ABSOLUTE_PATH, METHOD_INFO2, METHOD_INFO3,
			METHOD_ANY_MATCH = null;

	private static Class<?> CLASS_RESULT = null;

	@BeforeClass
	static void beforeClass() throws NoSuchMethodException, ClassNotFoundException {
		//
		final Class<?> clz = KeyStoreSslReport.class;
		//
		(METHOD_GET_NAME = clz.getDeclaredMethod("getName", Member.class)).setAccessible(true);
		//
		(METHOD_GET_CERTIFICATE = clz.getDeclaredMethod("getCertificate", KeyStore.class, String.class))
				.setAccessible(true);
		//
		(METHOD_LOAD = clz.getDeclaredMethod("load", KeyStore.class, InputStream.class, char[].class))
				.setAccessible(true);
		//
		(METHOD_IS_KEY_ENTRY = clz.getDeclaredMethod("isKeyEntry", KeyStore.class, String.class)).setAccessible(true);
		//
		(METHOD_IS_CERTIFICATE_ENTRY = clz.getDeclaredMethod("isCertificateEntry", KeyStore.class, String.class))
				.setAccessible(true);
		//
		(METHOD_IS_VALID = clz.getDeclaredMethod("isValid", DomainValidator.class, String.class)).setAccessible(true);
		//
		(METHOD_FORMAT = clz.getDeclaredMethod("format", DateFormat.class, Date.class)).setAccessible(true);
		//
		(METHOD_TO_CHAR_ARRAY = clz.getDeclaredMethod("toCharArray", String.class)).setAccessible(true);
		//
		(METHOD_LONGEST_COMMON_SUB_STRING = clz.getDeclaredMethod("longestCommonSubstring", String.class, String.class))
				.setAccessible(true);
		//
		(METHOD_SUBSTRACT = clz.getDeclaredMethod("substract", Date.class, Date.class)).setAccessible(true);
		//
		(METHOD_GET_ABSOLUTE_PATH = clz.getDeclaredMethod("getAbsolutePath", File.class)).setAccessible(true);
		//
		(METHOD_INFO2 = clz.getDeclaredMethod("info", Logger.class,
				CLASS_RESULT = Class.forName("org.apache.commons.lang3.KeyStoreSslReport$Result"))).setAccessible(true);
		//
		(METHOD_ANY_MATCH = clz.getDeclaredMethod("anyMatch", Stream.class, Predicate.class)).setAccessible(true);
		//
	}

	private static class IH implements InvocationHandler {

		private Boolean test, containsKey, hasMoreElements, add, anyMatch;

		private Integer size, length;

		@Override
		public Object invoke(final Object proxy, final Method method, final Object[] args) throws Throwable {
			//
			final String name = getName(method);
			//
			if (Objects.equals(method != null ? method.getReturnType() : null, Void.TYPE)) {
				//
				return null;
				//
			} // if
				//
			if (proxy instanceof Collection) {
				//
				if (Objects.equals(name, "size")) {
					//
					return size;
					//
				} else if (Objects.equals(name, "stream")) {
					//
					return null;
					//
				} else if (Objects.equals(name, "add")) {
					//
					return add;
					//
				} // if
					//
			} // if
				//
			if (proxy instanceof Map) {
				//
				if (Objects.equals(name, "containsKey")) {
					//
					return containsKey;
					//
				} else if (contains(Arrays.asList("get", "put", "entrySet", "keySet"), name)) {
					//
					return null;
					//
				} // if
					//
			} else if (Boolean.logicalOr(proxy instanceof Predicate, proxy instanceof ObjIntPredicate)
					&& Objects.equals(name, "test")) {
				//
				return test;
				//
			} else if (proxy instanceof FailableFunction && Objects.equals(name, "apply")) {
				//
				return null;
				//
			} else if (proxy instanceof Stream) {
				//
				if (contains(Arrays.asList("collect", "filter", "max"), name)) {
					//
					return null;
					//
				} else if (Objects.equals(name, "anyMatch")) {
					//
					return anyMatch;
					//
				} // if
					//
			} else if (proxy instanceof List && Objects.equals(name, "get")) {
				//
				return null;
				//
			} else if (proxy instanceof Member && Objects.equals(name, "getName")) {
				//
				return null;
				//
			} else if (proxy instanceof Entry && contains(Arrays.asList("getValue", "getKey"), name)) {
				//
				return null;
				//
			} else if (proxy instanceof Enumeration) {
				//
				if (Objects.equals(name, "hasMoreElements")) {
					//
					return hasMoreElements;
					//
				} else if (Objects.equals(name, "nextElement")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof XPath && Objects.equals(name, "evaluate")) {
				//
				return null;
				//
			} else if (proxy instanceof Node && Objects.equals(name, "getTextContent")) {
				//
				return null;
				//
			} else if (proxy instanceof NodeList) {
				//
				if (Objects.equals(name, "getLength")) {
					//
					return length;
					//
				} else if (Objects.equals(name, "item")) {
					//
					return null;
					//
				} // if
					//
			} // if
				//
			throw new Throwable(name);
			//
		}

	}

	private KeyStore keyStore = null;

	@BeforeMethod
	void beforeMethod() throws IllegalAccessException, InvocationTargetException, KeyStoreException {
		//
		Assert.assertNull(
				invoke(METHOD_LOAD, null, keyStore = KeyStore.getInstance(KeyStore.getDefaultType()), null, null));
		//
	}

	private static boolean contains(final Collection<?> instance, final Object item) {
		return instance != null && instance.contains(item);
	}

	private static String getName(final Member instance) throws Throwable {
		try {
			final Object obj = invoke(METHOD_GET_NAME, null, instance);
			if (obj == null) {
				return null;
			} else if (obj instanceof String) {
				return (String) obj;
			}
			throw new Throwable(Objects.toString(getClass(instance)));
		} catch (final InvocationTargetException e) {
			throw e.getTargetException();
		}
	}

	@Test
	void testNull() throws Throwable {
		//
		final Method[] ms = KeyStoreSslReport.class.getDeclaredMethods();
		//
		Method m = null;
		//
		Class<?>[] parameterTypes = null;
		//
		Class<?> parameterType = null;
		//
		Object result = null;
		//
		String toString, name = null;
		//
		Collection<Object> collection = null;
		//
		for (int i = 0; ms != null && i < ms.length; i++) {
			//
			if ((m = ArrayUtils.get(ms, i)) == null || m.isSynthetic()
					|| (parameterTypes = m.getParameterTypes()) == null) {
				//
				continue;
				//
			} // if
				//
			clear(collection = ObjectUtils.getIfNull(collection, ArrayList::new));
			//
			for (int j = 0; j < parameterTypes.length; j++) {
				//
				if (Objects.equals(parameterType = ArrayUtils.get(parameterTypes, j), Integer.TYPE)) {
					//
					add(collection, Integer.valueOf(0));
					//
				} else if (Objects.equals(parameterType, Long.TYPE)) {
					//
					add(collection, Long.valueOf(0));
					//
				} else if (Objects.equals(parameterType, Boolean.TYPE)) {
					//
					add(collection, Boolean.TRUE);
					//
				} else {
					//
					add(collection, null);
					//
				} // if
					//
			} // for
				//
			result = Narcissus.invokeStaticMethod(m, toArray(collection));
			//
			toString = Objects.toString(m);
			//
			if (contains(Arrays.asList(Boolean.TYPE, Integer.TYPE, Long.TYPE), m.getReturnType())
					|| Boolean.logicalAnd(Objects.equals(name = getName(m), "getEntry"),
							Arrays.equals(parameterTypes, new Class<?>[] { String.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "perform"),
							Arrays.equals(parameterTypes, new Class<?>[] { String.class, Map.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "perform2"),
							Arrays.equals(parameterTypes, new Class<?>[] { KeyStore.class, String.class }))) {
				//
				Assert.assertNotNull(result, toString);
				//
			} else {
				//
				Assert.assertNull(result, toString);
				//
			} // if
				//
		} // for
			//

	}

	private static <E> void add(final Collection<E> instance, final E item) {
		if (instance != null) {
			instance.add(item);
		}
	}

	private static void clear(final Collection<?> instance) {
		if (instance != null) {
			instance.clear();
		}
	}

	private static Object[] toArray(final Collection<?> instance) {
		return instance != null ? instance.toArray() : null;
	}

	@Test
	void testNotNull() throws Throwable {
		//
		final Method[] ms = KeyStoreSslReport.class.getDeclaredMethods();
		//
		Method m = null;
		//
		Class<?>[] parameterTypes = null;
		//
		Class<?> parameterType = null;
		//
		Object result = null;
		//
		String toString, name = null;
		//
		Collection<Object> collection = null;
		//
		IH ih = null;
		//
		for (int i = 0; ms != null && i < ms.length; i++) {
			//
			if ((m = ArrayUtils.get(ms, i)) == null || m.isSynthetic()
					|| (parameterTypes = m.getParameterTypes()) == null) {
				//
				continue;
				//
			} // if
				//
			clear(collection = ObjectUtils.getIfNull(collection, ArrayList::new));
			//
			for (int j = 0; j < parameterTypes.length; j++) {
				//
				if ((parameterType = ArrayUtils.get(parameterTypes, j)) != null && parameterType.isInterface()) {
					//
					if ((ih = ObjectUtils.getIfNull(ih, IH::new)) != null) {
						//
						final List<Field> fs = FieldUtils.getAllFieldsList(getClass(ih));
						//
						Field f = null;
						//
						for (int k = 0; fs != null && k < fs.size(); k++) {
							//
							if ((f = fs.get(k)) == null) {
								//
								continue;
								//
							} // if
								//
							final Class<?> type = f.getType();
							//
							if (Objects.equals(type, Boolean.class)) {
								//
								Narcissus.setField(ih, f, Boolean.TRUE);
								//
							} else if (Objects.equals(type, Integer.class)) {
								//
								Narcissus.setField(ih, f, Integer.valueOf(0));
								//
							} // if
								//
						} // for
							//
					} // if
						//
					add(collection, Reflection.newProxy(parameterType, ih = ObjectUtils.getIfNull(ih, IH::new)));
					//
				} else if (parameterType != null && parameterType.isArray()) {
					//
					add(collection, Array.newInstance(parameterType.getComponentType(), 0));
					//
				} else if (Objects.equals(parameterType, DateFormat.class)) {
					//
					add(collection, Narcissus.allocateInstance(SimpleDateFormat.class));
					//
				} else if (Objects.equals(parameterType, Integer.TYPE)) {
					//
					add(collection, Integer.valueOf(0));
					//
				} else if (Objects.equals(parameterType, Long.TYPE)) {
					//
					add(collection, Long.valueOf(0));
					//
				} else if (Objects.equals(parameterType, Boolean.TYPE)) {
					//
					add(collection, Boolean.TRUE);
					//
				} else if (Objects.equals(parameterType, KeyStore.class)) {
					//
					add(collection,
							Narcissus.allocateInstance(getClass(KeyStore.getInstance(KeyStore.getDefaultType()))));
					//
				} else if (Objects.equals(parameterType, InputStream.class)) {
					//
					add(collection, Narcissus.allocateInstance(ByteArrayInputStream.class));
					//
				} else if (Objects.equals(parameterType, Class.class)) {
					//
					add(collection, Class.class);
					//
				} else if (Objects.equals(parameterType, HttpsURLConnection.class)) {
					//
					add(collection, Narcissus
							.allocateInstance(Class.forName("sun.net.www.protocol.https.HttpsURLConnectionImpl")));
					//
				} else if (Objects.equals(parameterType, X509Certificate.class)) {
					//
					add(collection, Narcissus.allocateInstance(Class.forName("sun.security.x509.X509CertImpl")));
					//
				} else if (Objects.equals(parameterType, DocumentBuilderFactory.class)) {
					//
					add(collection, Narcissus.allocateInstance(getClass(DocumentBuilderFactory.newDefaultInstance())));
					//
				} else if (Objects.equals(parameterType, XPathFactory.class)) {
					//
					add(collection, Narcissus.allocateInstance(getClass(XPathFactory.newDefaultInstance())));
					//
				} else if (Objects.equals(parameterType, Number.class)) {
					//
					add(collection, Narcissus.allocateInstance(Long.class));
					//
				} else {
					//
					add(collection, Narcissus.allocateInstance(parameterType));
					//
				} // if
					//
			} // for
				//
			result = Narcissus.invokeStaticMethod(m, toArray(collection));
			//
			toString = Objects.toString(m);
			//
			if (contains(Arrays.asList(Boolean.TYPE, Integer.TYPE, Long.TYPE), m.getReturnType())
					|| Boolean.logicalAnd(Objects.equals(name = getName(m), "getClass"),
							Arrays.equals(parameterTypes, new Class<?>[] { Object.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "orElse"),
							Arrays.equals(parameterTypes, new Class<?>[] { Optional.class, Object.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "getEntry"),
							Arrays.equals(parameterTypes, new Class<?>[] { String.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "substract"),
							Arrays.equals(parameterTypes, new Class<?>[] { Date.class, Date.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "newDocumentBuilder"),
							Arrays.equals(parameterTypes, new Class<?>[] { DocumentBuilderFactory.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "perform"),
							Arrays.equals(parameterTypes, new Class<?>[] { String.class, Map.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "perform2"),
							Arrays.equals(parameterTypes, new Class<?>[] { KeyStore.class, String.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "iif"), Arrays.equals(parameterTypes,
							new Class<?>[] { Boolean.TYPE, Object.class, Object.class }))) {
				//
				Assert.assertNotNull(result, toString);
				//
			} else {
				//
				Assert.assertNull(result, toString);
				//
			} // if
				//
		} // for
			//
	}

	private static Class<?> getClass(final Object instance) {
		return instance != null ? instance.getClass() : null;
	}

	@Test
	public void testMain() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			XPathExpressionException, ParserConfigurationException, SAXException {
		//
		KeyStoreSslReport.main(new String[] { cast(String.class, Narcissus.allocateInstance(String.class)), "=", "= ",
				" =", "1=2", "1==" });
		//
		KeyStoreSslReport.main(new String[] { "config=." });
		//
		KeyStoreSslReport.main(new String[] { "config=pom.xml" });
		//
		final Class<?> clz = getClass();
		//
		final String name = clz != null ? clz.getName() : null;
		//
		final ProtectionDomain pd = clz != null ? clz.getProtectionDomain() : null;
		//
		final CodeSource cs = pd != null ? pd.getCodeSource() : null;
		//
		final URL location = cs != null ? cs.getLocation() : null;
		//
		KeyStoreSslReport.main(new String[] { "config=" + StringUtils.join(location != null ? location.getFile() : null,
				StringUtils.joinWith(".", name != null ? name.replace('.', '/') : null, "class")) });
		//
	}

	private static <T> T cast(final Class<T> clz, final Object instance) {
		return clz != null && clz.isInstance(instance) ? clz.cast(instance) : null;
	}

	private static Object invoke(final Method method, final Object instance, final Object... args)
			throws IllegalAccessException, InvocationTargetException {
		return method != null && method.getDeclaringClass() != null ? method.invoke(instance, args) : null;
	}

	@Test
	public void testGetCertificate() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertNull(invoke(METHOD_GET_CERTIFICATE, null, keyStore, null));
		//
		Assert.assertNull(invoke(METHOD_GET_CERTIFICATE, null, keyStore, ""));
		//
		Assert.assertNull(invoke(METHOD_GET_CERTIFICATE, null, keyStore, Narcissus.allocateInstance(String.class)));
		//
	}

	@Test
	public void testIsKeyEntry() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertEquals(invoke(METHOD_IS_KEY_ENTRY, null, keyStore, null), Boolean.FALSE);
		//
		Assert.assertEquals(invoke(METHOD_IS_KEY_ENTRY, null, keyStore, ""), Boolean.FALSE);
		//
		Assert.assertEquals(invoke(METHOD_IS_KEY_ENTRY, null, keyStore, Narcissus.allocateInstance(String.class)),
				Boolean.FALSE);
		//
	}

	@Test
	public void testIsCertificateEntry() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertEquals(invoke(METHOD_IS_CERTIFICATE_ENTRY, null, keyStore, null), Boolean.FALSE);
		//
		Assert.assertEquals(invoke(METHOD_IS_CERTIFICATE_ENTRY, null, keyStore, ""), Boolean.FALSE);
		//
		Assert.assertEquals(
				invoke(METHOD_IS_CERTIFICATE_ENTRY, null, keyStore, Narcissus.allocateInstance(String.class)),
				Boolean.FALSE);
		//
	}

	@Test
	public void testIsValid() throws IllegalAccessException, InvocationTargetException {
		//
		final DomainValidator domainValidator = DomainValidator.getInstance();
		//
		Assert.assertEquals(invoke(METHOD_IS_VALID, null, domainValidator, null), Boolean.FALSE);
		//
		Assert.assertEquals(invoke(METHOD_IS_VALID, null, domainValidator, ""), Boolean.FALSE);
		//
		Assert.assertEquals(invoke(METHOD_IS_VALID, null, domainValidator, "z.cn"), Boolean.TRUE);
		//
		Assert.assertEquals(invoke(METHOD_IS_VALID, null, domainValidator, Narcissus.allocateInstance(String.class)),
				Boolean.FALSE);
		//
		Assert.assertEquals(invoke(METHOD_IS_VALID, null, Narcissus.allocateInstance(DomainValidator.class), "z.cn"),
				Boolean.FALSE);
		//
	}

	@Test
	public void testFormat() throws IllegalAccessException, InvocationTargetException, ParseException {
		//
		final DateFormat df = new SimpleDateFormat("yyyy-MM-dd");
		//
		Assert.assertNull(invoke(METHOD_FORMAT, null, df, null));
		//
		final String string = "2001-02-03";
		//
		Assert.assertEquals(invoke(METHOD_FORMAT, null, df, df != null ? df.parse(string) : null), string);
		//
	}

	@Test
	public void testToCharArray() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertNotNull(invoke(METHOD_TO_CHAR_ARRAY, null, ""));
		//
	}

	@Test
	public void testSubtract() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertNull(invoke(METHOD_SUBSTRACT, null, new Date(), null));
		//
	}

	@Test
	public void testGetAbsolutePath() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertNotNull(invoke(METHOD_GET_ABSOLUTE_PATH, null, new File(".")));
		//
	}

	@Test
	public void testLongestCommonSubstring() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertEquals(invoke(METHOD_LONGEST_COMMON_SUB_STRING, null, "abcd", "bcde"), "bcd");
		//
	}

	@Test
	public void testInfo() throws IllegalAccessException, InvocationTargetException, ClassNotFoundException {
		//
		final Object result = Narcissus.allocateInstance(CLASS_RESULT);
		//
		FieldUtils.writeDeclaredField(result, "difference", Long.valueOf(-1), true);
		//
		Assert.assertNull(invoke(METHOD_INFO2, null, null, result));
		//
		FieldUtils.writeDeclaredField(result, "difference", Long.valueOf(1), true);
		//
		Assert.assertNull(invoke(METHOD_INFO2, null, null, result));
		//
		Assert.assertNull(invoke(METHOD_INFO3, null, null, null, Collections.singletonMap(null, null)));
		//
		Assert.assertNull(invoke(METHOD_INFO3, null, null, null, Collections.singletonMap(null,
				Narcissus.allocateInstance(Class.forName("sun.security.x509.X509CertImpl")))));
		//
	}

	@Test
	public void testAnyMatch() throws IllegalAccessException, InvocationTargetException {
		//
		final Stream<?> stream = Stream.empty();
		//
		Assert.assertEquals(invoke(METHOD_ANY_MATCH, null, stream, null), Boolean.FALSE);
		//
		Assert.assertEquals(invoke(METHOD_ANY_MATCH, null, stream, Predicates.alwaysTrue()), Boolean.FALSE);
		//
	}

}