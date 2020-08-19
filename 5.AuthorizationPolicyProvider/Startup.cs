using System.Security.Claims;
using _1.Basis.AuthorizationRequirements;
using _1.Basis.Controllers;
using _1.Basis.Transformer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace _1.Basis
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication("CookieAuth")
                .AddCookie("CookieAuth", config =>
                {
                    config.Cookie.Name = "Granma.Cookie";
                    config.LoginPath = "/Home/Authenticate";
                });

            services.AddAuthorization(config =>
            {
                //Custom requirements
                //---------------------
                config.AddPolicy("Claim.DoB", policyBuilder =>  // This is duplicate functionality of ".RequireClaim(ClaimTypes.DateOfBirth)"
                {
                    policyBuilder.RequireCustomeClaim(ClaimTypes.DateOfBirth);
                });
            });

            services.AddScoped<IAuthorizationHandler, CustomRequreClaimHandler>();
            services.AddScoped<IAuthorizationHandler, CookieJarAuthorizationHandler>();
            services.AddScoped<IClaimsTransformation, ClaimsTransformation>();

            services.AddControllersWithViews();

            ////This is global filter, will added to all controller methods. If you want to bypass need to add [AllowAnonymous] atribute
            //services.AddControllersWithViews(config =>
            //{
            //    var defaultAuthBuilder = new AuthorizationPolicyBuilder();
            //    var defaultAuthPolicy = defaultAuthBuilder

            //    //If I add Database claim, it will thro Access denied even in Index page
            //    //.RequireClaim(ClaimTypes.DateOfBirth)
            //    .RequireAuthenticatedUser()
            //    .Build();

            //    config.Filters.Add(new AuthorizeFilter(defaultAuthPolicy));
            //});

            services.AddRazorPages()
                .AddRazorPagesOptions(config => {
                    config.Conventions.AuthorizePage("/Razor/Secured");
                    config.Conventions.AuthorizePage("/Razor/Policy", "Claim.DoB");
                    config.Conventions.AuthorizeFolder("/RazorSecured");
                    config.Conventions.AllowAnonymousToPage("/RazorSecured/Anon");
                });
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
                endpoints.MapRazorPages();
            });
        }
    }

    public static class AuthorizationPolicyBuilderExtention
    {
        public static AuthorizationPolicyBuilder RequireCustomeClaim(this AuthorizationPolicyBuilder builder, string claim)
        {
            builder.AddRequirements(new CustomRequireClaim(claim));
            return builder;
        }
    }

}
