using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using Xunit;

namespace SecureLab.Api.Tests;

public sealed class SecurityTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers_Password")
        ?? throw new InvalidOperationException("Set local SeedUsers_Password outside Git.");

    // Сценарій A-01: Анонімний запит повертає 401 Unauthorized
    [Fact]
    public async Task A01_AnonymousRequest_Returns401()
    {
        using var client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var request = new
        {
            title = "Anon incident",
            description = "Authorization test",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow
        };

        using var response = await client.PostAsJsonAsync("/api/incidents", request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // Сценарій A-02: Авторизований вхід та перевірка /api/me
    [Fact]
    public async Task A02_LoginAndGetMe_ReturnsCurrentUserProfile()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);
        using var response = await client.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        using var document = System.Text.Json.JsonDocument.Parse(json);
        Assert.Equal("alice", document.RootElement.GetProperty("userName").GetString());
    }

    // Сценарій A-05: Спроба підміни ownerUserId в JSON ігнорується сервером
    [Fact]
    public async Task A05_OwnerCannotBeForgedInJson()
    {
        using var client = await factory.LoginAsync("bob", StudyPassword);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();

        var alice = await db.Users.SingleAsync(u => u.UserName == "alice");
        var bob = await db.Users.SingleAsync(u => u.UserName == "bob");

        var title = $"Owner test {Guid.NewGuid()}";
        var request = new
        {
            title,
            description = "Checking ownership",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow,
            ownerUserId = alice.Id // Передаємо чужий ID Аліси
        };

        using var response = await client.PostAsJsonAsync("/api/incidents", request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        // Перевіряємо фактичного власника у БД
        var incident = await db.Incidents.AsNoTracking().SingleAsync(i => i.Title == title);
        Assert.Equal(bob.Id, incident.OwnerUserId);     // Власником став Боб
        Assert.NotEqual(alice.Id, incident.OwnerUserId); // Підміна не пройшла
    }
}