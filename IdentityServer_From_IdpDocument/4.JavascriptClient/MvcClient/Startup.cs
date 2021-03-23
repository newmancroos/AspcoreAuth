using IdentityServer4;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.IdentityModel.Tokens.Jwt;
namespace MvcClient
{
    //Microsoft.AspNetCore.Authentication.OpenIdConnect   - For Ui support
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            JwtSecurityTokenHandler.DefaultMapInboundClaims = false;
            //JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = "Cookie";
                options.DefaultChallengeScheme = "oidc"; // when we need the user to login, we will be using the OpenID Connect protocal
            })
            .AddCookie("Cookie")
            .AddOpenIdConnect("oidc", options =>
            {
                options.Authority = "https://localhost:5001";
                options.ClientId = "mvc";
                options.ClientSecret = "secret";
                options.ResponseType = "code";

                //To pull user claims from the user object we need to add the following lines
                options.Scope.Add("profile");
                //options.Scope.Add("customprofile");
                // options.GetClaimsFromUserInfoEndpoint = true;
                options.SaveTokens = true;
                options.Scope.Add("api1");
                options.Scope.Add("offline_access");

            });
            //.AddGoogle("Google", options =>
            //{
            //    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
            //    options.ClientId = "163952891800-sbv0htp1modtge1kl4tj3b4ikud8jqm2.apps.googleusercontent.com";
            //    options.ClientSecret = "wna1c_KRl8wHXivvFzG0g_JU";
            //});
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
                //.RequireAuthorization();  //Disable anonymouse access to entire application. Can use [Authorize] to per Controller or Action
            });
        }
    }
}
