package io.nixer.springplugin.e2e.demo.attacks;

import java.io.IOException;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.CookieStore;
import java.net.HttpCookie;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Requires DemoApplication up and running.
 *
 * Created on 18/12/2019.
 *
 * @author Grzegorz Cwiak (gcwiak)
 */
class BruteForceAttackDemo {

    // TODO move this class to a separate, dedicated repository.

    private static final String DEFAULT_URI = "http://localhost:8080";

    private static final CookieManager cookieManager = new CookieManager();

    private static HttpClient client;
    private static CookieStore cookieStore;

    @BeforeAll
    static void setUpAll() {
        CookieHandler.setDefault(cookieManager);
        client = HttpClient.newBuilder()
                .cookieHandler(cookieManager)
                .build();

        cookieStore = cookieManager.getCookieStore();

        cookieStore.removeAll(); // FIXME should it be cleared before each test case iteration?
    }

    /**
     * Simulates brute-force attack by sending multiple invalid login requests for same username using unique IP addresses.
     * <br/>
     * Using multiple ip addresses to sent requests is achieved using forwarding headers.
     * <br/>
     * Each parameterized test iteration represents one login attempt.
     * <br/>
     * <br/>
     * <b>Results interpretation:</b>
     * <br/>All iterations pass successfully -> no protection mechanisms were triggered.
     * <br/>Subsequent iterations fail due to unexpected captcha tag -> captcha challenge protection was triggered.
     */
    @ParameterizedTest
    @CsvFileSource(resources = "/e2e/test-bruteforce.data.csv", numLinesToSkip = 1)
    void brute_force_attack_not_mitigated(String username, String password, String ip) throws IOException, InterruptedException {
        // given
        final HttpRequest loginFormRequest = HttpRequest.newBuilder()
                .uri(URI.create(uri("/login")))
                .headers(
                        "Content-Type", "application/x-www-form-urlencoded",
                        "X-Forwarded-For", ip
                )
                .GET()
                .build();

        // when
        final HttpResponse<String> loginFormResponse = client.send(loginFormRequest, HttpResponse.BodyHandlers.ofString());

        // then
        assertThat(loginFormResponse.statusCode()).isEqualTo(200);
        assertThat(cookieStore.getCookies()).extracting(HttpCookie::getName).contains("JSESSIONID");

        final Elements form = expectNode(Jsoup.parse(loginFormResponse.body()), "form.form-signin");
        expectNode(form, "input[name='username']");
        expectNode(form, "input[name='password']");

        final String csrfToken = expectNode(form, "input[name='_csrf']").val();
        assertThat(csrfToken).isNotBlank();

        assertThat(form.select("div.g-recaptcha").isEmpty()).isTrue();

        // given
        final HttpRequest loginRequest = HttpRequest.newBuilder()
                .uri(URI.create(uri("/login")))
                .headers(
                        "Content-Type", "application/x-www-form-urlencoded",
                        "X-Forwarded-For", ip,
                        "User-Agent", "random-UA" // FIXME make it actually random
                )
                .POST(HttpRequest.BodyPublishers.ofString( // TODO find better way for passing the following
                        "username=" + username
                                + "&" + "password=" + password
                                + "&" + "_csrf=" + csrfToken
                )).build();

        // when
        final HttpResponse<String> loginResponse = client.send(loginRequest, HttpResponse.BodyHandlers.ofString());

        // then
        assertThat(loginResponse.statusCode()).isEqualTo(302);
        assertThat(loginResponse.headers().allValues("Location")).containsExactly(uri("/login?error"));
    }

    private static String uri(final String path) {
        return DEFAULT_URI + path;
    }

    private Elements expectNode(final Elements elements, final String query) {
        Elements expected = elements.select(query);
        assertThat(expected.isEmpty()).isFalse();
        return expected;
    }

    private Elements expectNode(final Document document, final String query) {
        Elements expected = document.select(query);
        assertThat(expected.isEmpty()).isFalse();
        return expected;
    }
}