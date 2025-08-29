using DeviceInfoAPI.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddSingleton<IIpStorageService, IpStorageService>();
builder.Services.AddSingleton<IDeviceInfoService, DeviceInfoService>();

// Configure CORS to allow local access
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocal", policy =>
    {
        policy.WithOrigins("http://localhost:*", "https://localhost:*")
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

// Add Swagger/OpenAPI support
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors("AllowLocal");

// Define endpoints
app.MapGet("/", () => "Device Info API is running!");

app.MapGet("/api/device-info", (IDeviceInfoService deviceInfoService) =>
{
    var deviceInfo = deviceInfoService.GetDeviceInfo();
    return Results.Ok(deviceInfo);
})
.WithName("GetDeviceInfo")
.WithOpenApi();

app.MapGet("/api/device-info/async", async (IDeviceInfoService deviceInfoService) =>
{
    var deviceInfo = await deviceInfoService.GetDeviceInfoAsync();
    return Results.Ok(deviceInfo);
})
.WithName("GetDeviceInfoAsync")
.WithOpenApi();

app.MapGet("/api/health", () => Results.Ok(new { Status = "Healthy", Timestamp = DateTime.UtcNow }))
.WithName("HealthCheck")
.WithOpenApi();

// Start the application
Console.WriteLine("Starting Device Info API...");
Console.WriteLine($"Environment: {app.Environment.EnvironmentName}");
Console.WriteLine($"URLs: {string.Join(", ", app.Urls)}");

app.Run();
