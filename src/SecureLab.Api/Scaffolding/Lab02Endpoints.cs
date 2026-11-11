using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        // POST /api/incidents: серверна валідація та DTO
        app.MapPost("/api/incidents", async (
            CreateIncidentRequest request,
            HttpContext httpContext,
            UserManager<ApplicationUser> users,
            SecureLabDbContext db) =>
        {
            // 1. Поточний користувач з verified principal
            var currentUser = await users.GetUserAsync(httpContext.User);
            if (currentUser is null)
            {
                return Results.Unauthorized();
            }

            // 2. Валідація полів
            if (string.IsNullOrWhiteSpace(request.Title)
                || string.IsNullOrWhiteSpace(request.Description)
                || !request.OccurredAtUtc.HasValue)
            {
                return Results.BadRequest(new { message = "Invalid incident data" });
            }

            if (!Enum.TryParse<IncidentSeverity>(request.Severity, true, out var severity)
                || !Enum.IsDefined(severity))
            {
                return Results.BadRequest(new { message = "Invalid severity level" });
            }

            // 3. Створення інциденту
            var now = DateTimeOffset.UtcNow;
            var incident = new Incident
            {
                Id = Guid.NewGuid(),
                OwnerUserId = currentUser.Id, // сервер сам призначає власника
                Title = request.Title.Trim(),
                Description = request.Description.Trim(),
                Severity = severity,
                Status = IncidentStatus.New,
                OccurredAtUtc = request.OccurredAtUtc.Value.ToUniversalTime(),
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            };

            db.Incidents.Add(incident);
            await db.SaveChangesAsync();

            return Results.Created($"/api/incidents/{incident.Id}", new CreatedIncidentResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc));
        }).RequireAuthorization();

        // GET /api/incidents/search: безпечний пошук через LINQ
        app.MapGet("/api/incidents/search", async (
            string? q,
            string? sortBy,
            SecureLabDbContext db,
            CancellationToken ct) =>
        {
            if (sortBy is not (null or "" or "createdAtUtc" or "severity" or "status"))
            {
                return Results.ValidationProblem(
                    new Dictionary<string, string[]>
                    {
                        ["sortBy"] = ["Allowed values: createdAtUtc, severity, status."]
                    });
            }

            // Екранування спецсимволів ILIKE (\, %, _)
            var search = (q ?? "")
                .Replace("\\", "\\\\")
                .Replace("%", "\\%")
                .Replace("_", "\\_");

            var query = db.Incidents
                .AsNoTracking()
                .Where(i =>
                    EF.Functions.ILike(i.Title, "%" + search + "%", "\\") ||
                    EF.Functions.ILike(i.Description, "%" + search + "%", "\\"));

            IQueryable<Incident> sortedQuery = sortBy switch
            {
                "severity" => query
                    .OrderBy(i => i.Severity == IncidentSeverity.Critical ? 0 :
                                  i.Severity == IncidentSeverity.High ? 1 :
                                  i.Severity == IncidentSeverity.Medium ? 2 : 3)
                    .ThenBy(i => i.Id),

                "status" => query
                    .OrderBy(i => i.Status == IncidentStatus.New ? 0 :
                                  i.Status == IncidentStatus.Triaged ? 1 :
                                  i.Status == IncidentStatus.InProgress ? 2 :
                                  i.Status == IncidentStatus.Resolved ? 3 : 4)
                    .ThenBy(i => i.Id),

                _ => query
                    .OrderByDescending(i => i.CreatedAtUtc)
                    .ThenBy(i => i.Id)
            };

            var rows = await sortedQuery.Take(50).ToListAsync(ct);

            var result = rows.Select(row => new
            {
                row.Id,
                row.Title,
                row.Description,
                Severity = row.Severity.ToString(),
                Status = row.Status.ToString(),
                row.CreatedAtUtc
            });

            return Results.Ok(result);
        });
    }
}

// DTO
public sealed record CreateIncidentRequest(
    string? Title,
    string? Description,
    string? Severity,
    DateTimeOffset? OccurredAtUtc);

public sealed record CreatedIncidentResponse(
    Guid Id,
    string Title,
    string Description,
    string Severity,
    string Status,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset CreatedAtUtc);