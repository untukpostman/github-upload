using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Web.Http;
using FsgAdmin.Api.Web.AppComponent;
using FsgAdmin.Api.Web.Contracts;
using FsgAdmin.Api.Web.Middleware;
using FsgAdmin.Api.Web.Models;
using FsgAdmin.Api.Web.Models.Dto;
using FsgAdmin.Api.Web.Models.Form;
using FsgAdmin.Api.Web.Services;
using FsgAdmin.Component;

namespace FsgAdmin.Api.Web.Controllers
{
  [Authorize]
  [RoutePrefix("user")]
  public class UserController : ApiController
  {
    private readonly IPasswordEncoder _passwordEncoder;

    public UserController()
    {
      _passwordEncoder = new BCryptPasswordEncoder();
    }

    [HttpGet]
    [Route("profile")]
    public IHttpActionResult Profile()
    {
      var userId = Convert.ToUInt32(RequestContext.Principal.Identity.Name);
      User user = new User();
      if (!user.DAL_Load(userId))
      {
        return NotFound();
      }
      return Ok(new ResponseWrapper<object>(
        HttpStatusCode.OK,
        new
        {
          user.Username,
          user.FullName,
          user.Designation,
          user.MobileNumber,
          StaffCode = "",
          user.DateCreated,
          user.DateModified
        }
      ));
    }
    /// <summary>
    /// Provide login endpoint using POST /api/auth/get-token
    /// </summary>
    /// <param name="form">This is form/payload object that hold input request from request body.</param>
    [HttpPost]
    [Route("update-profile")]
    public IHttpActionResult UpdateProfile([FromBody] UpdateProfileForm form)
    {
      if (!ModelState.IsValid)
      {
        Dictionary<string, string> errorList = AppUtils.Validation.GetErrorDictionary(ModelState);
        return Content(
          HttpStatusCode.BadRequest, 
          new ResponseWrapper<object>(HttpStatusCode.BadRequest, errorList)
        );
      }

      var userId = Convert.ToUInt32(RequestContext.Principal.Identity.Name);
      User user = new User();
      if (!user.DAL_Load(userId))
      {
        return NotFound();
      }

      user.FullName = form.FullName;
      user.Designation = form.Designation;
      user.MobileNumber = form.MobileNumber;
      user.ModifiedBy = userId;

      if (user.DAL_UpdateProfile())
      {
        return Ok(new ResponseWrapper<bool>(HttpStatusCode.OK, true));
      }

      return InternalServerError();
    }

    /// <summary>
    /// Provide login endpoint using POST /api/auth/get-token
    /// </summary>
    /// <param name="form">This is form/payload object that hold input request from request body.</param>
    [HttpPost]
    [Route("change-password")]
    public IHttpActionResult UpdatePassword([FromBody] UpdatePasswordForm form)
    {
      Dictionary<string, string> errorList;
      if (!ModelState.IsValid)
      {
        errorList = AppUtils.Validation.GetErrorDictionary(ModelState);
        return Content(
          HttpStatusCode.BadRequest,
          new ResponseWrapper<object>(HttpStatusCode.BadRequest, errorList)
        );
      }

      uint userId = Convert.ToUInt32(RequestContext.Principal.Identity.Name);
      User user = new User();
      if (!user.DAL_Load(userId))
      {
        return NotFound();
      }

      //Later may move to its own validation that receive modelState as binding result
      if (!_passwordEncoder.IsMatch(form.CurrentPassword, user.Password))
      {
        ModelState.AddModelError("CurrentPassword", "Current Password is not valid.");
        errorList = AppUtils.Validation.GetErrorDictionary(ModelState);
        return Content(
          HttpStatusCode.BadRequest,
          new ResponseWrapper<object>(HttpStatusCode.BadRequest, errorList)
        );
      }

      user.Password = _passwordEncoder.HashPassword(form.NewPassword);
      user.ModifiedBy = userId;

      if (user.DAL_UpdatePassword())
      {
        return Ok(new ResponseWrapper<bool>(HttpStatusCode.OK, true));
      }

      return InternalServerError();
    }

    [HttpGet]
    [Route("~/users/")]
    public IHttpActionResult List([FromUri] ManageUserSearchForm form)
    {
      int pageNumber = form.PageNumber; //from input, should be validated: must start from 1
      int pageSize = form.PageSize; //from input, should be validated: must exist in options provided
      int startRowIndex = pageSize * (pageNumber - 1);

      List<User> users = Component.User.DAL_LoadManagementCustom(null, form.Username, null, form.IsActive, form.FullName, form.Designation, form.EmailAddress, form.MobileNumber, form.SortBy, form.SortType, startRowIndex, pageSize, out int intTotalRows);

      int totalPageNumber = (int)Math.Ceiling((double)intTotalRows / pageSize);
      int startRow = startRowIndex + (users.Count > 0 ? 1 : 0);
      int endRow = (startRowIndex + users.Count);
      var result = new
      {
        PageNumber = pageNumber,
        TotalPage = totalPageNumber,
        TotalRow = intTotalRows,
        StartRow = startRow,
        EndRow = endRow,
        Items = users.Select(item => new
        {
          item.UserId,
          item.Username,
          item.IsActive,
          item.FullName,
          item.Designation,
          item.EmailAddress,
          item.MobileNumber,
        })
      };

      return Ok(new ResponseWrapper<object>(HttpStatusCode.OK, result));
    }

    [AllowAnonymous]
    [HttpGet]
    [Route("view/{id}")]
    public IHttpActionResult View(uint id)
    {
      User user = new User();
      if (!user.DAL_Load(id))
      {
        return NotFound();
      }

      List<UserRole> userRoles = UserRole.DAL_LoadComplete(id, null, null, null, null);

      return Ok(new ResponseWrapper<object>(
        HttpStatusCode.OK,
        new
        {
          user.UserId,
          user.Username,
          user.IsActive,
          user.FullName,
          user.Designation,
          user.EmailAddress,
          user.MobileNumber,
          Roles = userRoles.Select(item => item.RoleId )
        }
      ));
    }

    [HttpPost]
    [AuthorizeAccessRight(new[] { AppModuleActivity.UserManage })]
    [Route("update/{id}")]
    public IHttpActionResult Update(uint id, [FromBody] UpdateUserForm form)
    {
      Dictionary<string, string> errorList;
      uint currentUserId = Convert.ToUInt32(RequestContext.Principal.Identity.Name);
      if (!ModelState.IsValid)
      {
        errorList = AppUtils.Validation.GetErrorDictionary(ModelState);
        return Content(
          HttpStatusCode.BadRequest,
          new ResponseWrapper<object>(HttpStatusCode.BadRequest, errorList)
        );
      }
      User user = new User();
      if (!user.DAL_Load(id))
      {
        return NotFound();
      }

      user.Username = form.Username;
      user.IsActive = form.IsActive;
      user.FullName = form.FullName;
      user.EmailAddress = form.EmailAddress;
      user.Designation = form.Designation;
      user.MobileNumber = form.MobileNumber;
      user.ModifiedBy = currentUserId;

      List<UserRole> userRoles = UserRole.DAL_Load(id, null, null, null, null);
      List<uint> willRetainUserRoleIds = userRoles
        .FindAll(item => form.Roles.Exists(nItem => nItem == item.RoleId))
        .ConvertAll(item => item.UserRoleId);
      List<uint> willAddRoleIds = form.Roles.FindAll(item => !userRoles.Exists(nItem => nItem.RoleId == item));

      var conn = AppSetting.Db.OpenConnection();
      var trans = conn.BeginTransaction();
      try
      {
        if (user.DAL_Update(conn, trans)
          && UserRole.DAL_DeleteByUserId(conn, trans, user.UserId, string.Join(",", willRetainUserRoleIds)))
        {
          bool hasErrorTransaction = willAddRoleIds.Exists(
            item => !new UserRole
            {
              UserId = user.UserId,
              RoleId = item,
              CreatedBy = currentUserId,
            }.DAL_AddExisting(conn, trans)
          );

          if (!hasErrorTransaction)
          {
            trans.Commit();
            return Ok(new ResponseWrapper<bool>(HttpStatusCode.OK, true));
          }
        }
        trans.Rollback();
      }
      catch (Exception)
      {
        trans.Rollback();
      }
      finally
      {
        AppSetting.Db.CloseConnection(ref conn);
      }

      ModelState.AddModelError("", "Failed to process your request");
      errorList = AppUtils.Validation.GetErrorDictionary(ModelState);
      return Content(
        HttpStatusCode.BadRequest,
        new ResponseWrapper<object>(HttpStatusCode.BadRequest, errorList)
      );
    }

    [HttpPost]
    [AuthorizeAccessRight(new[] { AppModuleActivity.UserAdd, AppModuleActivity.UserManage })]
    [Route("add")]
    public IHttpActionResult Add([FromBody] AddUserForm form)
    {
      Dictionary<string, string> errorList;
      if (!ModelState.IsValid)
      {
        errorList = AppUtils.Validation.GetErrorDictionary(ModelState);
        return Content(
          HttpStatusCode.BadRequest,
          new ResponseWrapper<object>(HttpStatusCode.BadRequest, errorList)
        );
      }

      uint loggedInUserId = Convert.ToUInt32(RequestContext.Principal.Identity.Name);

      User user = new User();
      user.Username = form.Username;
      user.IsActive = form.IsActive;
      user.FullName = form.FullName;
      user.EmailAddress = form.EmailAddress;
      user.Designation = form.Designation;
      user.MobileNumber = form.MobileNumber;
      user.UserTypeId = (byte)UserType.None;
      user.Password = _passwordEncoder.HashPassword("123");
      user.CreatedBy = loggedInUserId;

      var conn = AppSetting.Db.OpenConnection();
      var trans = conn.BeginTransaction();
      try
      {
        if (user.DAL_Add(conn, trans))
        {
          bool hasErrorTransaction = form.Roles.Exists(
            item =>
            {
              UserRole userRole = new UserRole
              {
                UserId = user.UserId,
                RoleId = item,
                CreatedBy = loggedInUserId,
              };
              return !userRole.DAL_Add(conn, trans);
            }
          );

          if (!hasErrorTransaction)
          {
            trans.Commit();
            return Ok(new ResponseWrapper<object>(HttpStatusCode.OK, new
            {
              Id = user.UserId
            }));
          }
        }
        trans.Rollback();
      }
      catch (Exception)
      {
        trans.Rollback();
      }
      finally
      {
        AppSetting.Db.CloseConnection(ref conn);
      }

      ModelState.AddModelError("", "Failed to process your request");
      errorList = AppUtils.Validation.GetErrorDictionary(ModelState);
      return Content(
        HttpStatusCode.BadRequest,
        new ResponseWrapper<object>(HttpStatusCode.BadRequest, errorList)
      );
    }

  }
}