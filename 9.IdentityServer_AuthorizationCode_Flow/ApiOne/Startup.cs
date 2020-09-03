using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace ApiOne
{
    public class Startup
    {
        //This is a Idp Api. An Api also can be a client
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(o =>
            {
                o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;//these two lines got it from the comments section of this tutorial. with out these line callint api giving no chalenge error.
                o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;   //these two lines got it from the comments section of this tutorial. with out these line callint api giving no chalenge error.
            })
            .AddJwtBearer("Bearer", config =>{
                config.Authority = "https://localhost:44320/";
                config.Audience = "ApiOne";
                //config.RequireHttpsMetadata = false;
            });
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
                endpoints.MapControllers();
            });
        }
    }
}
