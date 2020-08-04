using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using _2.IdentitySample.Data;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NETCore.MailKit.Extensions;
using NETCore.MailKit.Infrastructure.Internal;

namespace _2.IdentitySample
{
    public class Startup
    {
        private readonly IConfiguration _config;

        public Startup(IConfiguration config)
        {
            _config = config;
        }
        public void ConfigureServices(IServiceCollection services)
        {
            //services.AddAuthentication("CookieAuth")
            //    .AddCookie("CookieAuth", config =>
            //    {
            //        config.Cookie.Name = "Granma.Cookie";
            //        config.LoginPath = "/Home/Authenticate";
            //    });

            //We install EntityFrameworkCore and EntityFrameworkCore.Inmemory to handle In-Memory database 
            services.AddDbContext<AppDbContext>(confic => {
                confic.UseInMemoryDatabase("Memory");
            });

            //We need to install Identity to handle user Claims and Principal, UserManagement.
            //To connect Entity Framwork and Identity we need AspnetCore.Identity.EntityFramework nuget package
            services.AddIdentity<IdentityUser, IdentityRole>(config => {
                config.Password.RequiredLength = 4;
                config.Password.RequireDigit = false;
                config.Password.RequireNonAlphanumeric = false;
                config.Password.RequireUppercase = false;
                config.SignIn.RequireConfirmedEmail = true;
            })
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders();

            //In normal authentication we can use as above in the AddAuthentication but in Identity we hav to use like this
            services.ConfigureApplicationCookie(config =>
            {
                config.Cookie.Name = "Identity.Cookie";
                config.LoginPath = "/Home/Login";
            });

            //Mailkit is a Nuget package to send email. "NetCore.MailKit". so we can inject IEmailService
            //anywhere to send email
            var mailKitOptions = _config.GetSection("Email").Get<MailKitOptions>();
            services.AddMailKit(config => config.UseMailKit(mailKitOptions));

            services.AddControllersWithViews();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();  // If you put UseAuthorization before UseRoute then it will allow to authorize attributed method
                                     // So it should always after UserRouting

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
