export * from './page-meta.dto';
export * from './page-options.dto';
export * from './pagination.dto';

// @Get('/admin/pods')
// @UseGuards(AuthGuard)
// async getPodMetrics(@Query() query: GetPodMetricsDto & PaginationDto) {
//   const data = await this.analyticsService.getPodMetrics(query);
//   return {
//     data,
//     message: 'Pod Metrics Fetched Successfully',
//     success: true,
//   };
// }

// @Get('/admin/applications')
// @UseGuards(AuthGuard)
// async getApplicationMetrics(@Query() query: { timeRange?: string }) {
//   const data = await this.analyticsService.getApplicationMetrics(query);
//   return {
//     data,
//     message: 'Application Metrics Fetched Successfully',
//     success: true,
//   };
// }

// @Get('/admin/solo-projects')
// @UseGuards(AuthGuard)
// async getSoloProjectMetrics(@Query() query: { timeRange?: string }) {
//   const data = await this.analyticsService.getSoloProjectMetrics(query);
//   return {
//     data,
//     message: 'Solo Project Metrics Fetched Successfully',
//     success: true,
//   };
// }



// async getPodMetrics(query: GetPodMetricsDto & PaginationDto) {
//   try {
//     const {
//       dateFilter,
//       startDate,
//       endDate,
//       filter = PodFilterEnum.ALL,
//       page = 1,
//       limit = 10
//     } = query;

//     const searchQuery = dateFilter ?
//       { createdAt: this.getDateFilter(dateFilter, startDate, endDate) } :
//       {};

//     const allPods = await this.generatedEpicRepo.find({
//       ...searchQuery,
//       number_of_xterns: { $gt: 1 }
//     }).populate('prospectiveXtern.userId', 'firstName lastName avatar');

//     const thirtyDaysAgo = new Date();
//     thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

//     let filteredPods = allPods;
//     switch (filter) {
//       case PodFilterEnum.ACTIVE:
//         filteredPods = allPods.filter(p =>
//           new Date(p.lastActivityAt || p.updatedAt) >= thirtyDaysAgo
//         );
//         break;
//       case PodFilterEnum.ONGOING:
//         filteredPods = allPods.filter(p =>
//           p.generation_status === 'IN_PROGRESS' &&
//           new Date(p.lastActivityAt || p.updatedAt) >= thirtyDaysAgo
//         );
//         break;
//       case PodFilterEnum.COMPLETED:
//         filteredPods = allPods.filter(p => {
//           const completionPercentage = calculateIsCompleted(p.epics);
//           return completionPercentage === 100;
//         });
//         break;
//       case PodFilterEnum.INACTIVE:
//         filteredPods = allPods.filter(p =>
//           new Date(p.lastActivityAt || p.updatedAt) < thirtyDaysAgo
//         );
//         break;
//     }

//     const skip = (page - 1) * limit;
//     const total = filteredPods.length;
//     const paginatedPods = filteredPods
//       .slice(skip, skip + limit)
//       .map(pod => ({
//         id: pod._id,
//         title: pod.aiProjectTitle,
//         participatingXterns: pod.prospectiveXtern.map(x => x.userId),
//         skillLevel: pod.complexity_level,
//         status: pod.generation_status,
//         createdAt: pod.createdAt,
//         lastActivity: pod.lastActivityAt || pod.updatedAt
//       }));

//     return {
//       overview: {
//         totalPods: allPods.length,
//         status: {
//           active: allPods.filter(p => p.generation_status === 'IN_PROGRESS').length,
//           ongoing: allPods.filter(p => p.generation_status === 'IN_PROGRESS').length,
//           completed: allPods.filter(p => p.generation_status === 'COMPLETED').length,
//           inactive: allPods.filter(p =>
//             new Date(p.lastActivityAt || p.updatedAt) < thirtyDaysAgo
//           ).length
//         }
//       },
//       metrics: {
//         teamPods: {
//           total: allPods.filter(p => !p.tech_lead_needed).length,
//           completionRate: this.calculateCompletionRate(allPods.filter(p => !p.tech_lead_needed)),
//           abandonmentRate: this.calculateAbandonmentRate(allPods.filter(p => !p.tech_lead_needed))
//         },
//         techLeadPods: {
//           total: allPods.filter(p => p.tech_lead_needed).length,
//           completionRate: this.calculateCompletionRate(allPods.filter(p => p.tech_lead_needed)),
//           abandonmentRate: this.calculateAbandonmentRate(allPods.filter(p => p.tech_lead_needed))
//         }
//       },
//       pods: new PaginationResultDto(paginatedPods, total, { limit, page })
//     };
//   } catch (error) {
//     ErrorHelper.BadRequestException(error);
//   }
// }

// async getApplicationMetrics(query: { timeRange?: string }) {
//   try {
//     const dateFilter = this.getDateFilter(query.timeRange);
//     const queryFilter = dateFilter ? { createdAt: dateFilter } : {};

//     const applications = await this.applicationRepo
//       .find(queryFilter)
//       .populate('assessmentResults');

//     const completedAssessments = applications.filter(app =>
//       app.assessmentResults && app.assessmentResults.length > 0
//     );

//     const successfulApplications = applications.filter(app =>
//       app.status === 'ACCEPTED'
//     );

//     const abandonedApplications = applications.filter(app =>
//       app.status === 'ABANDONED'
//     );

//     const averageCompletionTime = this.calculateAverageApplicationTime(applications);

//     return {
//       total: applications.length,
//       metrics: {
//         completedAssessments: completedAssessments.length,
//         successfulApplications: successfulApplications.length,
//         abandonedApplications: abandonedApplications.length,
//         averageCompletionTime,
//         rejectionReasons: this.aggregateRejectionReasons(applications)
//       }
//     };
//   } catch (error) {
//     ErrorHelper.BadRequestException(error);
//   }
// }

// async getSoloProjectMetrics(query: { timeRange?: string }) {
//   try {
//     const dateFilter = this.getDateFilter(query.timeRange);
//     const queryFilter = dateFilter ? { createdAt: dateFilter } : {};

//     const soloProjects = await this.generatedEpicRepo.find({
//       ...queryFilter,
//       number_of_xterns: 1  // Changed to filter for exactly 1 xtern
//     });

//     const thirtyDaysAgo = new Date();
//     thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

//     const getInactiveProjects = (projects: Generated_Epic[]) =>
//       projects.filter(p => new Date(p.lastActivityAt || p.updatedAt) < thirtyDaysAgo);

//     return {
//       total: soloProjects.length,
//       status: {
//         active: soloProjects.filter(p => p.generation_status === 'IN_PROGRESS').length,
//         completed: soloProjects.filter(p => p.generation_status === 'COMPLETED').length,
//         ongoing: soloProjects.filter(p => p.generation_status === 'IN_PROGRESS').length,
//         inactive: getInactiveProjects(soloProjects).length
//       },
//       metrics: {
//         completionRate: this.calculateProjectCompletionRate(soloProjects),
//         abandonmentRate: this.calculateProjectAbandonmentRate(soloProjects)
//       }
//     };
//   } catch (error) {
//     ErrorHelper.BadRequestException(error);
//   }
// }

// private calculateCompletionRate(items: any[]) {
//   if (items.length === 0) return 0;
//   const completed = items.filter(item => item.status === 'COMPLETED').length;
//   return (completed / items.length) * 100;
// }

// private calculateAbandonmentRate(items: any[]) {
//   if (items.length === 0) return 0;
//   const abandoned = items.filter(item => item.status === 'ABANDONED').length;
//   return (abandoned / items.length) * 100;
// }

// private calculateAverageApplicationTime(applications: Application[]) {
//   if (applications.length === 0) return 0;
//   const completedApplications = applications.filter(app => app.status === 'ACCEPTED');
//   const totalTime = completedApplications.reduce((sum, app) => {
//     const completionTime = new Date(app.updatedAt).getTime() - new Date(app.createdAt).getTime();
//     return sum + completionTime;
//   }, 0);
//   return totalTime / completedApplications.length / (1000 * 60 * 60 * 24); // Convert to days
// }

// private aggregateRejectionReasons(applications: Application[]) {
//   const reasons = applications
//     .filter(app => app.status === 'REJECTED' && app.rejectionReason)
//     .map(app => app.rejectionReason);
//   return this.countOccurrences(reasons);
// }

// private countOccurrences(arr: any[]) {
//   return arr.reduce((acc, val) => {
//     acc[val] = (acc[val] || 0) + 1;
//     return acc;
//   }, {});
// }

// private calculateProjectCompletionRate(projects: Generated_Epic[]) {
//   if (projects.length === 0) return 0;
//   const completed = projects.filter(p => p.status === 'COMPLETED').length;
//   return (completed / projects.length) * 100;
// }

// private calculateProjectAbandonmentRate(projects: Generated_Epic[]) {
//   if (projects.length === 0) return 0;
//   const abandoned = projects.filter(p => p.status === 'ABANDONED').length;
//   return (abandoned / projects.length) * 100;
// }


// metrics: {
//     projectCompletion: {
//       total: projects.length,
    //   completed: projects.filter(p => p.status === 'COMPLETED').length,
    //   ongoing: projects.filter(p => p.status === 'ONGOING').length,
    //   abandoned: projects.filter(p => p.status === 'ABANDONED').length
    // },
    // collaboration: {
    //   ticketCompletionRate: completedTickets.length / tickets.length * 100,
    //   averageTicketTime: this.calculateAverageTicketTime(completedTickets)
    // },
//   }