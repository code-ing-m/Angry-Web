using AngryWeb.Service;
using AngryWeb.Service.Core;

var builder = Host.CreateApplicationBuilder(args);

// Configure Windows Service lifetime
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "AngryWebService";
});

// Register Core Components
builder.Services.AddSingleton<ConfigManager>();
builder.Services.AddSingleton<PatternMatcher>();
builder.Services.AddSingleton<TemporaryAccessManager>();
builder.Services.AddSingleton<AutoUpdateManager>();
builder.Services.AddSingleton<SiteVisitLogger>();
builder.Services.AddSingleton<BlockPageServer>();
builder.Services.AddSingleton<ProxyFilterEngine>();

builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
