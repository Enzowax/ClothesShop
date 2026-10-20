using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

builder.Services.AddDbContext<ShopDbContext>();

var hasher = new PasswordHasher<User>();

var key = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
var validation = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "ClothesShop",
    ValidateAudience = true,
    ValidAudience = "ClothesShopApi",
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = key,
    ValidateLifetime = true,
    ClockSkew = TimeSpan.Zero,
    NameClaimType = "name",
    RoleClaimType = "role"
};

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = validation;
    });
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ShopDbContext>();
    context.Database.EnsureCreated();
    if (!context.Users.Any())
    {
        var manager = new User { Login = "manager", Phone = "+79000000000", Address = "Склад", Role = "Manager" };
        manager.PasswordHash = hasher.HashPassword(manager, "Demo123!");
        context.Users.Add(manager);

        context.Clothes.AddRange(
            new Clothing { Name = "Футболка базовая белая", Price = 990, Description = "100% хлопок", Type = "Футболка",
                Sizes = [new() { Letter = "S", Number = 44, Quantity = 10 }, new() { Letter = "M", Number = 46, Quantity = 15 }, new() { Letter = "L", Number = 48, Quantity = 5 }] },
            new Clothing { Name = "Футболка оверсайз черная", Price = 1490, Description = "Свободный крой", Type = "Футболка",
                Sizes = [new() { Letter = "M", Number = 46, Quantity = 8 }, new() { Letter = "XL", Number = 52, Quantity = 3 }] },
            new Clothing { Name = "Худи серое", Price = 3490, Description = "С начесом", Type = "Худи",
                Sizes = [new() { Letter = "L", Number = 48, Quantity = 4 }] });
        context.SaveChanges();
    }
}

app.MapPost("/api/auth/register", async (ShopDbContext context, RegisterRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.Login) || string.IsNullOrWhiteSpace(request.Password))
        return Results.BadRequest(new { message = "Логин и пароль обязательны" });
    if (await context.Users.AnyAsync(u => u.Login == request.Login))
        return Results.Conflict(new { message = "Логин уже занят" });

    var user = new User { Login = request.Login, Phone = request.Phone, Address = request.Address, Role = "User" };
    user.PasswordHash = hasher.HashPassword(user, request.Password);
    context.Users.Add(user);
    await context.SaveChangesAsync();
    return Results.Created($"/api/users/{user.Id}", new { user.Id, user.Login, user.Phone, user.Address, user.Role });
}).AllowAnonymous();

app.MapPost("/api/auth/login", async (ShopDbContext context, LoginRequest request) =>
{
    var user = await context.Users.FirstOrDefaultAsync(u => u.Login == request.Login);
    if (user == null || string.IsNullOrWhiteSpace(request.Password))
        return Results.Challenge();

    var result = hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
    if (result == PasswordVerificationResult.Failed)
        return Results.Challenge();

    return Results.Ok(new
    {
        access_token = CreateToken(user),
        token_type = "Bearer"
    });
}).AllowAnonymous();

app.MapGet("/api/me", (ClaimsPrincipal user) =>
{
    return Results.Ok(new
    {
        id = user.FindFirst("sub")?.Value,
        login = user.Identity?.Name,
        role = user.FindFirst("role")?.Value
    });
}).RequireAuthorization();

app.MapGet("/api/clothes", async (ShopDbContext context) =>
    Results.Json(await context.Clothes.Include(c => c.Sizes).ToListAsync()));

app.MapGet("/api/clothes/search", async (ShopDbContext context, string name) =>
    Results.Json(await context.Clothes.Include(c => c.Sizes).Where(c => c.Name.Contains(name)).ToListAsync()));

app.MapPatch("/api/clothes/{id}/hide", (ShopDbContext context, int id) => SetAvailability(context, id, false))
    .RequireAuthorization(policy => policy.RequireAuthenticatedUser().RequireRole("Manager"));

app.MapPatch("/api/clothes/{id}/show", (ShopDbContext context, int id) => SetAvailability(context, id, true))
    .RequireAuthorization(policy => policy.RequireAuthenticatedUser().RequireRole("Manager"));

app.MapPatch("/api/sizes/{id}/quantity", async (ShopDbContext context, int id, QuantityRequest request) =>
{
    if (request.Quantity < 0)
        return Results.BadRequest(new { message = "Количество не может быть отрицательным" });

    var size = await context.Sizes.FirstOrDefaultAsync(s => s.Id == id);
    if (size == null) return Results.NotFound(new { message = "Размер не найден" });

    size.Quantity = request.Quantity;
    await context.SaveChangesAsync();
    return Results.Json(size);
}).RequireAuthorization(policy => policy.RequireAuthenticatedUser().RequireRole("Manager"));

app.MapPost("/api/orders", async (ShopDbContext context, ClaimsPrincipal user, CreateOrderRequest request) =>
{
    if (request.Items == null || request.Items.Count == 0)
        return Results.BadRequest(new { message = "Заказ пуст" });

    var order = new Order { UserId = GetUserId(user), CreatedAt = DateTime.Now, Status = OrderStatus.Created };
    foreach (var item in request.Items)
    {
        var size = await context.Sizes.Include(s => s.Clothing).FirstOrDefaultAsync(s => s.Id == item.SizeId);
        if (size == null)
            return Results.NotFound(new { message = $"Размер {item.SizeId} не найден" });
        if (!size.Clothing.IsAvailable)
            return Results.BadRequest(new { message = $"Товар '{size.Clothing.Name}' снят с продажи" });
        if (item.Quantity <= 0 || size.Quantity < item.Quantity)
            return Results.BadRequest(new { message = $"Недостаточно товара '{size.Clothing.Name}' размера {size.Letter}" });

        size.Quantity -= item.Quantity;
        size.Clothing.PurchaseCount += item.Quantity;
        order.Items.Add(new OrderItem { ClothingSizeId = size.Id, Quantity = item.Quantity });
    }

    context.Orders.Add(order);
    await context.SaveChangesAsync();
    var created = await OrdersWithDetails(context).FirstAsync(o => o.Id == order.Id);
    return Results.Created($"/api/orders/{order.Id}", created);
}).RequireAuthorization();

app.MapGet("/api/orders", async (ShopDbContext context, ClaimsPrincipal user, OrderStatus status) =>
{
    var orders = OrdersWithDetails(context).Where(o => o.Status == status);
    if (!user.IsInRole("Manager"))
    {
        var userId = GetUserId(user);
        orders = orders.Where(o => o.UserId == userId);
    }
    return Results.Json(await orders.ToListAsync());
}).RequireAuthorization();

app.MapGet("/api/users/{userId}/orders", async (ShopDbContext context, ClaimsPrincipal user, int userId) =>
{
    if (!user.IsInRole("Manager") && GetUserId(user) != userId)
        return Results.Forbid();

    return Results.Json(await OrdersWithDetails(context).Where(o => o.UserId == userId).ToListAsync());
}).RequireAuthorization();

app.MapPatch("/api/orders/{id}/status", async (ShopDbContext context, int id, StatusRequest request) =>
{
    var order = await context.Orders.FirstOrDefaultAsync(o => o.Id == id);
    if (order == null) return Results.NotFound(new { message = "Заказ не найден" });

    order.Status = request.Status;
    await context.SaveChangesAsync();
    return Results.Json(new { order.Id, order.Status });
}).RequireAuthorization(policy => policy.RequireAuthenticatedUser().RequireRole("Manager"));

app.Run();

string CreateToken(User user)
{
    var claims = new[]
    {
        new Claim("sub", user.Id.ToString()),
        new Claim("name", user.Login),
        new Claim("role", user.Role)
    };

    var token = new JwtSecurityToken(
        issuer: "ClothesShop",
        audience: "ClothesShopApi",
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(15),
        signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));

    return new JwtSecurityTokenHandler().WriteToken(token);
}

static int GetUserId(ClaimsPrincipal user) => int.Parse(user.FindFirst("sub")!.Value);

static IQueryable<Order> OrdersWithDetails(ShopDbContext context) => context.Orders
    .Include(o => o.User)
    .Include(o => o.Items).ThenInclude(i => i.ClothingSize).ThenInclude(s => s.Clothing);

static async Task<IResult> SetAvailability(ShopDbContext context, int id, bool isAvailable)
{
    var clothing = await context.Clothes.FirstOrDefaultAsync(c => c.Id == id);
    if (clothing == null) return Results.NotFound(new { message = "Товар не найден" });

    clothing.IsAvailable = isAvailable;
    await context.SaveChangesAsync();
    return Results.Json(new { clothing.Id, clothing.Name, clothing.IsAvailable });
}

public enum OrderStatus { Created, Paid, Shipped, Delivered, Cancelled }

public class Clothing
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public decimal Price { get; set; }
    public string Description { get; set; } = "";
    public int PurchaseCount { get; set; }
    public string Type { get; set; } = "";
    public bool IsAvailable { get; set; } = true;
    public List<ClothingSize> Sizes { get; set; } = [];
}

public class ClothingSize
{
    public int Id { get; set; }
    public string Letter { get; set; } = "";
    public int Number { get; set; }
    public int Quantity { get; set; }
    public int ClothingId { get; set; }
    public Clothing Clothing { get; set; } = null!;
}

public class User
{
    public int Id { get; set; }
    public string Phone { get; set; } = "";
    public string Address { get; set; } = "";
    public string Login { get; set; } = "";
    [JsonIgnore] public string PasswordHash { get; set; } = "";
    public string Role { get; set; } = "User";
    public List<Order> Orders { get; set; } = [];
}

public class Order
{
    public int Id { get; set; }
    public DateTime CreatedAt { get; set; }
    public OrderStatus Status { get; set; }
    public int UserId { get; set; }
    public User User { get; set; } = null!;
    public List<OrderItem> Items { get; set; } = [];
}

public class OrderItem
{
    public int Id { get; set; }
    public int Quantity { get; set; }
    public int OrderId { get; set; }
    [JsonIgnore] public Order Order { get; set; } = null!;
    public int ClothingSizeId { get; set; }
    public ClothingSize ClothingSize { get; set; } = null!;
}

public class ShopDbContext : DbContext
{
    public DbSet<Clothing> Clothes => Set<Clothing>();
    public DbSet<ClothingSize> Sizes => Set<ClothingSize>();
    public DbSet<User> Users => Set<User>();
    public DbSet<Order> Orders => Set<Order>();
    public DbSet<OrderItem> OrderItems => Set<OrderItem>();

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        => optionsBuilder.UseSqlServer("Data Source=.\\SQLEXPRESS;Initial Catalog=ClothesShop;Integrated Security=True;Trust Server Certificate=True");

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>().HasIndex(u => u.Login).IsUnique();
        modelBuilder.Entity<Clothing>().Property(c => c.Price).HasPrecision(10, 2);
        modelBuilder.Entity<Order>().Property(o => o.Status).HasConversion<string>();
        modelBuilder.Entity<OrderItem>().HasOne(i => i.ClothingSize).WithMany().OnDelete(DeleteBehavior.Restrict);
    }
}

public record RegisterRequest(string Login, string Password, string Phone, string Address);
public record LoginRequest(string Login, string Password);
public record QuantityRequest(int Quantity);
public record StatusRequest(OrderStatus Status);
public record OrderItemRequest(int SizeId, int Quantity);
public record CreateOrderRequest(List<OrderItemRequest> Items);
