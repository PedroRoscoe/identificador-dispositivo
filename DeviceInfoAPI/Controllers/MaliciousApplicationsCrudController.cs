using DeviceInfoAPI.Models;
using DeviceInfoAPI.Services;
using Microsoft.AspNetCore.Mvc;

namespace DeviceInfoAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
public class MaliciousApplicationsCrudController : ControllerBase
{
    private readonly IMaliciousApplicationsStorageService _storageService;
    private readonly ILogger<MaliciousApplicationsCrudController> _logger;

    public MaliciousApplicationsCrudController(
        IMaliciousApplicationsStorageService storageService,
        ILogger<MaliciousApplicationsCrudController> logger)
    {
        _storageService = storageService;
        _logger = logger;
    }

    /// <summary>
    /// Get all categories
    /// </summary>
    [HttpGet("categories")]
    public async Task<ActionResult<List<string>>> GetCategories()
    {
        try
        {
            var categories = await _storageService.GetCategoriesAsync();
            return Ok(categories);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting categories");
            return StatusCode(500, "Internal server error getting categories");
        }
    }

    /// <summary>
    /// Get applications by category
    /// </summary>
    [HttpGet("categories/{category}")]
    public async Task<ActionResult<List<MaliciousApplicationDefinition>>> GetApplicationsByCategory(string category)
    {
        try
        {
            var applications = await _storageService.GetApplicationsByCategoryAsync(category);
            return Ok(applications);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting applications for category {Category}", category);
            return StatusCode(500, "Internal server error getting applications");
        }
    }

    /// <summary>
    /// Get a specific application
    /// </summary>
    [HttpGet("categories/{category}/applications/{applicationName}")]
    public async Task<ActionResult<MaliciousApplicationDefinition>> GetApplication(string category, string applicationName)
    {
        try
        {
            var application = await _storageService.GetApplicationAsync(category, applicationName);
            if (application == null)
            {
                return NotFound($"Application '{applicationName}' not found in category '{category}'");
            }
            return Ok(application);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting application {AppName} from category {Category}", applicationName, category);
            return StatusCode(500, "Internal server error getting application");
        }
    }

    /// <summary>
    /// Add a new application to a category
    /// </summary>
    [HttpPost("categories/{category}/applications")]
    public async Task<ActionResult<object>> AddApplication(string category, [FromBody] MaliciousApplicationDefinition application)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(application.Name))
            {
                return BadRequest("Application name is required");
            }

            var success = await _storageService.AddApplicationAsync(category, application);
            if (success)
            {
                return CreatedAtAction(
                    nameof(GetApplication), 
                    new { category, applicationName = application.Name }, 
                    new { message = "Application added successfully", application });
            }
            else
            {
                return BadRequest("Failed to add application. It may already exist.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding application {AppName} to category {Category}", application.Name, category);
            return StatusCode(500, "Internal server error adding application");
        }
    }

    /// <summary>
    /// Update an existing application
    /// </summary>
    [HttpPut("categories/{category}/applications/{applicationName}")]
    public async Task<ActionResult<object>> UpdateApplication(string category, string applicationName, [FromBody] MaliciousApplicationDefinition updatedApplication)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(updatedApplication.Name))
            {
                return BadRequest("Application name is required");
            }

            var success = await _storageService.UpdateApplicationAsync(category, applicationName, updatedApplication);
            if (success)
            {
                return Ok(new { message = "Application updated successfully", application = updatedApplication });
            }
            else
            {
                return NotFound($"Application '{applicationName}' not found in category '{category}'");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating application {AppName} in category {Category}", applicationName, category);
            return StatusCode(500, "Internal server error updating application");
        }
    }

    /// <summary>
    /// Remove an application from a category
    /// </summary>
    [HttpDelete("categories/{category}/applications/{applicationName}")]
    public async Task<ActionResult<object>> RemoveApplication(string category, string applicationName)
    {
        try
        {
            var success = await _storageService.RemoveApplicationAsync(category, applicationName);
            if (success)
            {
                return Ok(new { message = "Application removed successfully" });
            }
            else
            {
                return NotFound($"Application '{applicationName}' not found in category '{category}'");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing application {AppName} from category {Category}", applicationName, category);
            return StatusCode(500, "Internal server error removing application");
        }
    }

    /// <summary>
    /// Get statistics about the malicious applications database
    /// </summary>
    [HttpGet("statistics")]
    public async Task<ActionResult<object>> GetStatistics()
    {
        try
        {
            var totalCount = await _storageService.GetTotalApplicationsCountAsync();
            var countByCategory = await _storageService.GetApplicationsCountByCategoryAsync();
            var categories = await _storageService.GetCategoriesAsync();

            var statistics = new
            {
                totalApplications = totalCount,
                totalCategories = categories.Count,
                applicationsByCategory = countByCategory,
                categories = categories,
                lastUpdated = DateTime.UtcNow
            };

            return Ok(statistics);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting statistics");
            return StatusCode(500, "Internal server error getting statistics");
        }
    }

    /// <summary>
    /// Check if a category exists
    /// </summary>
    [HttpGet("categories/{category}/exists")]
    public async Task<ActionResult<bool>> CategoryExists(string category)
    {
        try
        {
            var exists = await _storageService.CategoryExistsAsync(category);
            return Ok(exists);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking if category {Category} exists", category);
            return StatusCode(500, "Internal server error checking category existence");
        }
    }

    /// <summary>
    /// Check if an application exists in a category
    /// </summary>
    [HttpGet("categories/{category}/applications/{applicationName}/exists")]
    public async Task<ActionResult<bool>> ApplicationExists(string category, string applicationName)
    {
        try
        {
            var exists = await _storageService.ApplicationExistsAsync(category, applicationName);
            return Ok(exists);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking if application {AppName} exists in category {Category}", applicationName, category);
            return StatusCode(500, "Internal server error checking application existence");
        }
    }

    /// <summary>
    /// Search applications by name across all categories
    /// </summary>
    [HttpGet("search")]
    public async Task<ActionResult<List<object>>> SearchApplications([FromQuery] string query)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(query))
            {
                return BadRequest("Search query is required");
            }

            var results = new List<object>();
            var categories = await _storageService.GetCategoriesAsync();

            foreach (var category in categories)
            {
                var applications = await _storageService.GetApplicationsByCategoryAsync(category);
                var matchingApps = applications.Where(a => 
                    a.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                    a.Description.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                    a.ProcessNames.Any(p => p.Contains(query, StringComparison.OrdinalIgnoreCase))
                );

                foreach (var app in matchingApps)
                {
                    results.Add(new
                    {
                        category = category,
                        application = app
                    });
                }
            }

            return Ok(results);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error searching applications with query: {Query}", query);
            return StatusCode(500, "Internal server error searching applications");
        }
    }

    /// <summary>
    /// Export all data (for backup purposes)
    /// </summary>
    [HttpGet("export")]
    public async Task<ActionResult<MaliciousApplicationsData>> ExportData()
    {
        try
        {
            var data = await _storageService.LoadDataAsync();
            return Ok(data);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error exporting data");
            return StatusCode(500, "Internal server error exporting data");
        }
    }

    /// <summary>
    /// Import data (for restore purposes)
    /// </summary>
    [HttpPost("import")]
    public async Task<ActionResult<object>> ImportData([FromBody] MaliciousApplicationsData data)
    {
        try
        {
            if (data?.Categories == null)
            {
                return BadRequest("Invalid data format");
            }

            await _storageService.SaveDataAsync(data);
            return Ok(new { message = "Data imported successfully", importedCategories = data.Categories.Count });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error importing data");
            return StatusCode(500, "Internal server error importing data");
        }
    }
}

