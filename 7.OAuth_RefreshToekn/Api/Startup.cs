using Api.AuthRequirement;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Api
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            //for refresh token changes. This will ensure to throw 401 error instead of complex errors.
            services.AddAuthentication("DefaultAuth")
                .AddScheme<AuthenticationSchemeOptions, CustomeAuthenticationHandler>("DefaultAuth", null);


            services.AddAuthorization(config=> {
                var defaultAuthBuilder = new AuthorizationPolicyBuilder();
                var defaultAuthPolicy = defaultAuthBuilder
                .AddRequirements(new JwtRequirement())
                .Build();

                config.DefaultPolicy = defaultAuthPolicy;
            });

            services.AddScoped<IAuthorizationHandler, JwtRequirementHandler>();
            services.AddHttpClient()
                .AddHttpContextAccessor();  //allow access to HttpContext

            services.AddControllers();
        }
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
